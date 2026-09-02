# Kubernetes Enforcement Reference Profile

This is a local, disposable reference profile. It is an executable security
lab for one named environment: kind v0.33.0, Kubernetes v1.36.4, and Calico v3.32.2.
Calico is the NetworkPolicy-capable CNI in this profile; a Kubernetes
NetworkPolicy object without an enforcing CNI has no effect.

The kind node and lab base image are digest-addressed. The runner first verifies
the complete upstream Calico v3.32.2 manifest by SHA-256, then replaces its
three exact release-tag image references with the multi-architecture digests in
`kind/versions.json` before applying it. Deployed image references and runtime
image IDs are both checked. Version selection follows the official
[kind configuration](https://kind.sigs.k8s.io/docs/user/configuration/),
[Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/),
and [Calico Kubernetes requirements](https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements)
documentation.

The bounded question is whether these exact workloads and ports behave as
follows under the retained manifest and runtime digests:

```text
agent -> Interlock gateway -> MCP test server     allowed
agent -> MCP test server directly                 denied
unrelated probe -> MCP test server directly       denied
Interlock gateway -> MCP test server              allowed
```

The runner must prove the same live MCP endpoints are reachable before the
isolation policy is applied. DNS is tested separately. It then applies the
policy, proves direct denial using real pods and multiple clients, proves the
mediated path, and runs three separate controls:

1. **Live policy-removal reachability control.** It deletes the relevant
   NetworkPolicies in `interlock-agent` and `interlock-mcp`, then proves the same
   direct MCP Service and Pod-IP targets are reachable. This establishes that
   the targets and harness are reachable when the network boundary is removed.
2. **Live restoration control.** It reapplies the committed NetworkPolicies and
   proves the direct MCP Service target is denied again. This establishes that
   the observed denial depends on the restored policy boundary.
3. **Evidence-integrity mutation control.** Independently of policy removal, it
   copies the post-restoration report, changes `KE-016.actual_result` from
   `network_denied` to `allowed`, and proves the verifier rejects the mutation
   with the bounded `result mismatch` category. This establishes verifier
   integrity; it is not a live policy-removal result.

Policy removal proves live reachability; a separate synthetic mutation proves verifier integrity.
A failed positive control stops the run; it cannot be relabelled as network
enforcement.

## Evidence boundaries

- Network denial evidence is a bounded source-pod connection result, paired
  with a same-target policy-off positive control, successful DNS resolution,
  Calico readiness/version data, and exact deployed policy/config digests.
- Interlock audit evidence is produced only by the mediated `/mcp/call` and its
  verified hash-chain receipt.
- Deployment/configuration evidence records selected workload identities,
  policies, versions, source SHA, manifest/config digests, and runtime image IDs.

The retained report includes a sorted `namespace/name` map for every live
NetworkPolicy observed from the Kubernetes API in the four profile namespaces
after policy restoration. Each entry contains only `apiVersion`, `kind`,
`namespace`, `name`, `podSelector`, `policyTypes`, `ingress`, and `egress`, plus
a SHA-256 hash of that canonical payload. UID, resource version, managed fields,
timestamps, annotations, status, and other API metadata are excluded. A
set-level SHA-256 digest binds the complete map to the exact source SHA and
manifest-bundle digest.

The retained-evidence verifier independently reconstructs the expected
canonical map from the checked-out `manifests/network-policies.yaml`. It
requires exact namespace/name-set equality, exact canonical content, exact
per-policy hashes, and exact set-level digest equality. Missing, unexpected,
duplicate, malformed, partial, rehashed-but-changed, or source/manifest-mismatched
policy evidence fails closed. A policy count alone is not accepted as policy
identity or enforcement-intent evidence.

Calico can block direct packets before reaching the gateway. This profile does not make Interlock observe
traffic blocked before reaching the gateway, and it
does not create an Interlock audit event for those packets.

## Reproduction

Prerequisites are Docker Engine, kubectl, Python 3.12, and network access to the
exact pinned kind release, kind node image, Calico manifest, base image, and
Python packages. The runner creates and later deletes only a uniquely named
kind cluster with the `interlock-k8s-evidence-` prefix.

```powershell
python scripts/run_kubernetes_enforcement_acceptance.py `
  --output .artifacts/kubernetes-enforcement-<git-sha> `
  --source-sha <exact-40-character-git-sha>

python scripts/verify_kubernetes_enforcement_evidence.py `
  .artifacts/kubernetes-enforcement-<git-sha>/report.json `
  --source-sha <same-exact-git-sha>
```

The output directory must not already exist. The runner verifies clean source
identity, downloads the exact Calico manifest and kind binary into a private
temporary directory, verifies their SHA-256 values, builds and loads a
source-bound lab image, runs every required case, scans retained artifacts, and
deletes the cluster even on failure. Skipped, missing, duplicate, stale,
malformed, partial, failed, errored, xfailed, or xpassed cases are rejection
conditions, not evidence.

## Exact scope and limitations

This profile proves only the documented workload paths in the named local lab
at the recorded source, manifest, configuration, CNI, node-image, and lab-image
digests. It does not prove production, managed Kubernetes, all CNIs, cloud
firewall correctness, universal bypass prevention, tenant isolation, mTLS,
identity assurance, universal agent security, complete SSRF prevention,
complete DNS-rebinding prevention, compliance, or certification.

The canonical NetworkPolicy snapshot proves what the named Kubernetes API
reported for the disposable run and binds it to the checked-out source. It is
not, by itself, proof that a CNI enforced those objects; the separate live
reachability and restoration controls supply the bounded enforcement evidence.

It does not replace workload identity, authorization, secrets management,
sandboxing, egress controls, SIEM, or incident response. Those controls remain
necessary according to the deployment's threat model. The profile also does not
change or broaden the separate Docker Phase 2 evidence.

Application pods have no ServiceAccount token and no Kubernetes API allowance.
The gateway's local/dev URL guard is intentionally not the control under test:
the MCP fixture is a private cluster Service, while Calico supplies the tested
network boundary. No customer, cloud, production, or existing cluster is an
allowed target for this runner.
