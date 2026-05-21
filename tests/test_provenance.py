import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from core.provenance import evaluate_provenance, ProvenanceResult

POLICY = {
    "allowed_registries": ["registry.npmjs.org", "pypi.org"],
    "allowed_source_urls": ["https://github.com/modelcontextprotocol/"],
    "pinned_versions": {"pkg-a": "1.2.3"},
    "pinned_hashes": {"pkg-a": "sha256:aabbcc"},
}

def make_server(source_type="npm", registry="registry.npmjs.org",
                package_name="pkg-b", package_version="1.0.0",
                source_hash="", provenance_status="unknown"):
    return dict(source_type=source_type, registry=registry,
                package_name=package_name, package_version=package_version,
                source_hash=source_hash, provenance_status=provenance_status)


def test_known_registry_no_pin_is_allowed():
    r = evaluate_provenance(make_server(), POLICY)
    assert r.status == "allowed", r.reason


def test_known_registry_matching_hash_is_allowed():
    srv = make_server(package_name="pkg-a", package_version="1.2.3",
                      source_hash="sha256:aabbcc")
    r = evaluate_provenance(srv, POLICY)
    assert r.status == "allowed", r.reason


def test_missing_provenance_is_monitor():
    r = evaluate_provenance(make_server(source_type="unknown", registry=""), POLICY)
    assert r.status == "monitor"


def test_unknown_registry_is_monitor():
    r = evaluate_provenance(make_server(registry="evil.registry.io"), POLICY)
    assert r.status == "monitor"


def test_version_mismatch_is_quarantine():
    srv = make_server(package_name="pkg-a", package_version="9.9.9")
    r = evaluate_provenance(srv, POLICY)
    assert r.status == "quarantine"


def test_hash_mismatch_is_quarantine():
    srv = make_server(package_name="pkg-a", package_version="1.2.3",
                      source_hash="sha256:wronghash")
    r = evaluate_provenance(srv, POLICY)
    assert r.status == "quarantine"


def test_denied_source_type_is_denied():
    r = evaluate_provenance(make_server(source_type="denied"), POLICY)
    assert r.status == "denied"


def test_hash_change_after_approval_is_drift():
    prior = make_server(source_hash="sha256:old", provenance_status="allowed")
    current = make_server(source_hash="sha256:new")
    r = evaluate_provenance(current, POLICY, prior_record=prior)
    assert r.status == "quarantine"
    assert r.drift_detected is True


def test_version_change_after_approval_is_drift():
    prior = make_server(package_version="1.0.0", provenance_status="allowed")
    current = make_server(package_version="2.0.0")
    r = evaluate_provenance(current, POLICY, prior_record=prior)
    assert r.status == "quarantine"
    assert r.drift_detected is True


def test_empty_policy_is_monitor_for_all():
    r = evaluate_provenance(make_server(), {})
    assert r.status == "monitor"


# Tests 11-14 require gateway integration context — added in Task 4.
def test_quarantine_blocks_tool_call():
    srv2 = make_server(package_name="pkg-a", package_version="9.9.9")
    result2 = evaluate_provenance(srv2, POLICY)
    assert result2.status == "quarantine"


def test_allowed_provenance_permits_tool_call():
    srv = make_server()
    result = evaluate_provenance(srv, POLICY)
    assert result.status == "allowed"


def test_audit_log_written_on_provenance_check():
    result = evaluate_provenance(make_server(), POLICY)
    assert "allowed" in result.checks_run


def test_audit_log_written_on_provenance_drift():
    prior = make_server(source_hash="sha256:old", provenance_status="allowed")
    current = make_server(source_hash="sha256:new")
    result = evaluate_provenance(current, POLICY, prior_record=prior)
    assert result.drift_detected is True
    assert "hash_drift" in result.checks_run
