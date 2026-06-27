# Live Kubernetes Readback Proof

Date verified: 2026-06-27

This note records Interlock's credential-gated live Kubernetes/kubectl proof against a local Docker Desktop Kubernetes context. It is a proof artifact for a non-production local cluster, not EKS/GKE/AKS certification and not production-cluster validation.

## Claim

Interlock has live local Kubernetes/kubectl sandbox proof for provider-readback drift: when a tool claims dry-run/no-effect but Kubernetes state changes, Interlock detects the contradiction, classifies it as critical, and quarantines. Clean inventory and server-side dry-run controls stay allowed, and risky planned chains are denied before execution.

## Threat Model Proven

The tested Kubernetes scenario covers infra drift that static tool approval misses:

1. Interlock reads Kubernetes sandbox state before a target operation.
2. The target operation claims dry-run/preview/no-effect semantics.
3. Kubernetes state changes anyway through a real kubectl apply/delete canary.
4. Interlock reads Kubernetes state again.
5. Interlock compares evidence-safe before/after state profiles.
6. Hidden apply/delete is classified as critical/quarantine.
7. Dangerous multi-step chains such as secret read -> pod exec and inventory -> namespace delete are denied before execution.

This proves a class of infra drift that manifest/schema diffing alone cannot detect: same approved tool idea, but the actual cluster state changes.

## Verified Result

Command:

```bash
INTERLOCK_ALLOW_LIVE_KUBERNETES_PROOFS=1 \
INTERLOCK_KUBERNETES_CONTEXT=docker-desktop \
INTERLOCK_KUBERNETES_NAMESPACE=interlock-k8s-proof \
INTERLOCK_KUBERNETES_CANARY_LABEL=interlock-k8s-canary-001 \
python3 demo/run_kubernetes_live_proof_pack.py
```

Result:

```text
PASS live_kubectl_inventory_no_change_control severity=none decision=allow findings=none
PASS live_kubectl_server_dry_run_control severity=none decision=allow findings=none
PASS live_kubectl_hidden_apply_readback_drift severity=critical decision=quarantine findings=readback_state_changed_after_no_effect_expected,silent_side_effect_drift,effect_response_contradicted_by_readback
PASS live_kubectl_expected_apply_allowed_control severity=none decision=allow findings=none
PASS live_kubectl_hidden_delete_readback_drift severity=critical decision=quarantine findings=readback_state_changed_after_no_effect_expected,silent_side_effect_drift
PASS live_kubectl_secret_read_to_exec_chain_drift severity=critical decision=deny findings=chain_secret_to_execution
PASS live_kubectl_inventory_to_delete_namespace_chain_drift severity=critical decision=deny findings=chain_preview_to_destructive
```

## What Passed

- Read-only inventory no-change control stayed allowed.
- Server-side dry-run control stayed allowed.
- Hidden apply was detected by before/after Kubernetes readback and quarantined.
- Expected apply stayed allowed.
- Hidden delete was detected by before/after Kubernetes readback and quarantined.
- Secret read -> pod exec planned chain was denied before execution.
- Inventory/read -> namespace delete planned chain was denied before execution.

## Evidence Safety

The live harness does not store:

- kubeconfig contents
- service-account tokens
- cluster credentials
- raw Kubernetes object names
- full manifests
- cloud credentials

It stores or reports:

- context, namespace, canary labels, and object identities as hashes
- before/after provider profile hashes
- finding types, severity, decision, and receipt metadata

## Safety Gates

The live harness:

- exits as a safe skip unless `INTERLOCK_ALLOW_LIVE_KUBERNETES_PROOFS=1` is set
- requires `INTERLOCK_KUBERNETES_CONTEXT`; it never uses the current kubectl context implicitly
- requires `INTERLOCK_KUBERNETES_NAMESPACE` to start with `interlock-`
- should only run against Docker Desktop, kind, minikube, or a tightly scoped sandbox cluster

## Honest Limitations

This proof does not claim:

- EKS certification
- GKE certification
- AKS certification
- production-cluster validation
- coverage of every Kubernetes API edge case
- automatic rollback of the first sandbox canary side effect

This proof does claim:

- live local Kubernetes execution through kubectl
- before/after Kubernetes readback behavior
- hidden apply/delete side-effect drift detection
- critical/quarantine classification for no-effect-expected Kubernetes state changes
- clean false-positive controls for inventory and server-side dry-run
- pre-execution chain denial for secret -> exec and inventory -> delete namespace flows
- evidence-safe handling of Kubernetes state

## Recommended Public Wording

Use:

> Interlock has live local Kubernetes/kubectl sandbox proof for provider-readback drift: hidden apply/delete side effects were detected as critical/quarantine through before/after Kubernetes state readback, while inventory and server-side dry-run controls stayed allowed. It also denied secret -> exec and inventory -> namespace-delete planned chains before execution. The proof is credential-gated, non-production, and stores hashes rather than kubeconfig contents, tokens, raw object names, or manifests.

Do not use:

> Interlock is EKS/GKE/AKS certified.

Do not use:

> Interlock proves every Kubernetes API edge case.
