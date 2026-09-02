"""Truth-boundary checks for the Kubernetes enforcement operator guide."""

from pathlib import Path

README = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "kubernetes-enforcement"
    / "README.md"
)


def test_readme_states_exact_environment_and_evidence_boundaries():
    text = " ".join(README.read_text(encoding="utf-8").lower().split())

    required = [
        "local, disposable reference profile",
        "kind v0.33.0",
        "kubernetes v1.36.4",
        "calico v3.32.2",
        "networkpolicy-capable cni",
        "does not make interlock observe",
        "blocked before reaching the gateway",
        "network denial evidence",
        "interlock audit evidence",
        "deployment/configuration evidence",
        "sorted `namespace/name` map",
        "per-policy hashes",
        "manifest-bundle digest",
        "canonical source-text bundle digests",
        "not raw working-tree-byte digests",
        "normalizes crlf to lf",
        "rejects bare cr",
        "without parsing or reserializing yaml or json",
        "policy count alone is not accepted",
        "not, by itself, proof that a cni enforced",
        "separate live reachability and restoration controls",
        "does not prove production",
        "managed kubernetes",
        "all cnis",
        "cloud firewall",
        "universal bypass",
        "tenant isolation",
        "mtls",
        "identity assurance",
        "workload identity",
        "secrets management",
        "sandboxing",
        "siem",
        "incident response",
    ]
    for phrase in required:
        assert phrase in text


def test_readme_does_not_make_forbidden_broad_claims():
    text = " ".join(README.read_text(encoding="utf-8").lower().split())
    forbidden = [
        "works on every kubernetes",
        "all traffic is controlled by interlock",
        "provides complete ssrf prevention",
        "provides complete dns-rebinding prevention",
        "soc 2 compliant",
        "certified",
        "production proven",
    ]
    for phrase in forbidden:
        assert phrase not in text
