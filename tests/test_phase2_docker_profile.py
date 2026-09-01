from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy" / "phase2-docker"
COMPOSE = yaml.safe_load((PROFILE / "compose.yaml").read_text("utf-8"))
POLICY = (PROFILE / "squid.conf").read_text("utf-8")
WORKFLOW = yaml.safe_load(
    (ROOT / ".github" / "workflows" / "tests.yml").read_text("utf-8")
)
SQUID_IMAGE = "ghcr.io/cybozu/squid:7.6.0.1@sha256:b5fff668ddbf5738a779ada37893569e6640d2a2ac384a834095ac443d12d60a"
ISOLATED_GATEWAY_OPTIONS = {
    "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
    "com.docker.network.bridge.gateway_mode_ipv6": "isolated",
}


def test_phase2_topology_is_internal_dual_stack_and_has_no_published_ports():
    networks = COMPOSE["networks"]
    assert set(networks) == {"app_net", "origin_net", "denied_net"}
    assert all(network["internal"] is True for network in networks.values())
    assert all(network["enable_ipv6"] is True for network in networks.values())
    assert networks["app_net"]["driver_opts"] == ISOLATED_GATEWAY_OPTIONS
    for service in COMPOSE["services"].values():
        assert "ports" not in service
        assert "extra_hosts" not in service
        assert service.get("network_mode") != "host"


def test_only_application_network_requires_isolated_ipv4_and_ipv6_gateway_mode():
    networks = COMPOSE["networks"]
    assert networks["app_net"]["driver_opts"] == ISOLATED_GATEWAY_OPTIONS
    assert "driver_opts" not in networks["origin_net"]
    assert "driver_opts" not in networks["denied_net"]


def test_only_squid_bridges_application_to_origin_and_denied_networks():
    services = COMPOSE["services"]
    assert set(services["interlock"]["networks"]) == {"app_net"}
    assert set(services["acceptance"]["networks"]) == {"app_net"}
    assert set(services["postgres"]["networks"]) == {"app_net"}
    assert set(services["redis"]["networks"]) == {"app_net"}
    assert set(services["dns"]["networks"]) == {"app_net"}
    assert set(services["squid"]["networks"]) == {
        "app_net",
        "origin_net",
        "denied_net",
    }
    assert set(services["origin"]["networks"]) == {"origin_net"}
    assert set(services["denied_sink"]["networks"]) == {"denied_net"}
    assert services["certgen"]["network_mode"] == "none"


def test_compose_separates_deployable_boundary_from_acceptance_instrumentation():
    boundaries = COMPOSE["x-phase2-boundaries"]
    assert boundaries["deployable"] == {
        "application_network": "app_net",
        "upstream_network": "operator-provided",
    }
    assert boundaries["acceptance_only"] == {
        "networks": ["origin_net", "denied_net"],
        "services": ["acceptance", "certgen", "denied_sink", "origin"],
    }


def test_enforced_application_profile_is_explicit_and_ambient_values_are_hostile():
    environment = COMPOSE["services"]["interlock"]["environment"]
    assert environment["INTERLOCK_EGRESS_PROFILE"] == "enforced"
    assert environment["INTERLOCK_OUTBOUND_HTTP_PROXY"] == "http://squid:3128"
    assert environment["INTERLOCK_PROTECT_OUTBOUND_URLS"] == "true"
    assert environment["NO_PROXY"] == "*"
    assert environment["no_proxy"] == "*"
    assert "postgres" in environment["DATABASE_URL"]
    assert "redis" in environment["REDIS_URL"]


def test_squid_is_exactly_pinned_non_intercepting_and_default_deny():
    assert COMPOSE["services"]["squid"]["image"] == SQUID_IMAGE
    lowered = POLICY.lower()
    assert "ssl_bump" not in lowered
    assert "https_port" not in lowered
    assert "via off" not in lowered
    assert "http_access deny all" in POLICY
    assert "http_access deny denied_destination" in POLICY
    assert "http_access deny !allowed_domains" in POLICY
    assert "http_access deny proxy_credentials" in POLICY
    assert "forward_max_tries 1" in POLICY
    assert "connect_retries 0" in POLICY
    assert "server_persistent_connections off" in POLICY
    assert "client_persistent_connections off" in POLICY
    assert "positive_dns_ttl 60 seconds" in POLICY
    assert "ipcache_size 4096" in POLICY
    allowed = {
        line.strip()
        for line in (PROFILE / "allowed-domains.txt").read_text("utf-8").splitlines()
        if line.strip()
    }
    assert len(allowed) == 108
    assert len(allowed) < 4096
    assert ".phase2.test" not in allowed


def test_squid_log_format_omits_request_targets_and_sensitive_headers():
    log_line = next(
        line for line in POLICY.splitlines() if line.startswith("logformat ")
    )
    assert "%ru" not in log_line
    assert "%>h" not in log_line
    assert "%<h" not in log_line
    assert "%rm" in log_line
    assert "%<a" in log_line


def test_phase2_ci_job_is_exact_head_and_blocking():
    job = WORKFLOW["jobs"]["phase2-docker"]
    assert "continue-on-error" not in json_text(job)
    assert job["timeout-minutes"] == 30
    steps = job["steps"]
    pull_checkout = next(
        step for step in steps if step["name"] == "Checkout pull-request head"
    )
    push_checkout = next(step for step in steps if step["name"] == "Checkout event SHA")
    assert pull_checkout["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"
    assert push_checkout["with"]["ref"] == "${{ github.sha }}"
    source = next(step for step in steps if step.get("id") == "source")
    assert "git rev-parse HEAD" in source["run"]
    assert "git status --porcelain" in source["run"]
    setup = next(step for step in steps if step["name"] == "Set up pinned Python")
    assert setup["with"]["python-version"] == "3.12"
    acceptance = next(step for step in steps if step.get("id") == "acceptance")
    evidence = next(step for step in steps if step.get("id") == "evidence")
    assert "if" not in acceptance
    assert "if" not in evidence
    assert "run_phase2_docker_acceptance.py" in acceptance["run"]
    assert "verify_phase2_docker_evidence.py" in evidence["run"]
    upload = next(
        step for step in steps if step["name"] == "Upload Docker Phase 2 evidence"
    )
    assert upload["with"]["if-no-files-found"] == "error"
    assert upload["with"]["name"] == "phase2-docker-${{ steps.source.outputs.sha }}"


def json_text(value) -> str:
    return json.dumps(value, sort_keys=True)
