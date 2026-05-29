import logging
from dataclasses import dataclass, field

logger = logging.getLogger("interlock.provenance")


@dataclass
class ProvenanceResult:
    status: str  # allowed | monitor | quarantine | denied
    reason: str
    checks_run: list = field(default_factory=list)
    drift_detected: bool = False


def evaluate_provenance(
    server_record: dict, policy: dict, prior_record: dict | None = None
) -> ProvenanceResult:
    """
    Evaluate a server's provenance metadata against the operator policy.

    server_record: dict with keys from mcp_servers provenance columns.
    policy: dict with keys allowed_registries, allowed_source_urls,
            pinned_versions, pinned_hashes.
    prior_record: the previously stored server_record, used for drift detection.
                  Pass None on first registration.
    """
    checks: list[str] = []

    source_type = (server_record.get("source_type") or "unknown").strip()
    registry = (server_record.get("registry") or "").strip()
    pkg_name = (server_record.get("package_name") or "").strip()
    pkg_version = (server_record.get("package_version") or "").strip()
    src_hash = (server_record.get("source_hash") or "").strip()

    allowed_registries = policy.get("allowed_registries") or []
    pinned_versions = policy.get("pinned_versions") or {}
    pinned_hashes = policy.get("pinned_hashes") or {}

    # Operator hard-deny
    if source_type == "denied":
        checks.append("source_type_denied")
        return ProvenanceResult(
            status="denied",
            reason="source_type is explicitly denied.",
            checks_run=checks,
        )

    # Drift detection — runs before policy so drift always quarantines regardless of registry status
    if prior_record is not None:
        prior_hash = (prior_record.get("source_hash") or "").strip()
        prior_version = (prior_record.get("package_version") or "").strip()
        prior_status = (prior_record.get("provenance_status") or "unknown").strip()
        if prior_status == "allowed":
            if src_hash and prior_hash and src_hash != prior_hash:
                checks.append("hash_drift")
                return ProvenanceResult(
                    status="quarantine",
                    reason="source_hash changed after prior approval.",
                    checks_run=checks,
                    drift_detected=True,
                )
            if pkg_version and prior_version and pkg_version != prior_version:
                checks.append("version_drift")
                return ProvenanceResult(
                    status="quarantine",
                    reason="package_version changed after prior approval.",
                    checks_run=checks,
                    drift_detected=True,
                )

    # Missing provenance
    if not registry or source_type == "unknown":
        checks.append("missing_provenance")
        return ProvenanceResult(
            status="monitor",
            reason="No registry or source_type provided.",
            checks_run=checks,
        )

    # No policy configured — can't assert anything is allowed
    if not allowed_registries:
        checks.append("no_registry_policy")
        return ProvenanceResult(
            status="monitor",
            reason="No allowed_registries configured in policy.",
            checks_run=checks,
        )

    # Unknown registry
    if registry not in allowed_registries:
        checks.append("unknown_registry")
        return ProvenanceResult(
            status="monitor",
            reason=f"Registry '{registry}' is not in allowed_registries.",
            checks_run=checks,
        )

    checks.append("registry_ok")

    # Version pin check
    if pkg_name in pinned_versions:
        pinned_ver = pinned_versions[pkg_name]
        if pkg_version != pinned_ver:
            checks.append("version_mismatch")
            return ProvenanceResult(
                status="quarantine",
                reason=f"Version '{pkg_version}' does not match pinned '{pinned_ver}'.",
                checks_run=checks,
            )
        checks.append("version_ok")

    # Hash pin check
    if pkg_name in pinned_hashes:
        pinned_hash = pinned_hashes[pkg_name]
        if src_hash != pinned_hash:
            checks.append("hash_mismatch")
            return ProvenanceResult(
                status="quarantine",
                reason=f"source_hash does not match pinned hash for '{pkg_name}'.",
                checks_run=checks,
            )
        checks.append("hash_ok")

    checks.append("allowed")
    return ProvenanceResult(
        status="allowed", reason="All provenance checks passed.", checks_run=checks
    )
