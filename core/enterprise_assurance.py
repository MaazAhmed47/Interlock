"""Enterprise assurance helpers for proof scoping and compliance posture."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

REQUIRED_PRODUCTION_CONTROLS = [
    "written_approval",
    "non_customer_canary",
    "rollback_plan",
    "maintenance_window",
    "readback_plan",
]


def assess_production_proof_request(request: Dict[str, Any]) -> Dict[str, Any]:
    request = dict(request or {})
    environment = str(request.get("environment") or "").strip().lower()
    if environment not in {"prod", "production"}:
        return {
            "ready": True,
            "mode": "non_production_or_sandbox",
            "missing_controls": [],
            "limits": [
                "Non-production proof still requires bounded canary inputs and evidence-safe logging."
            ],
        }

    missing = [
        control
        for control in REQUIRED_PRODUCTION_CONTROLS
        if not bool(request.get(control))
    ]
    return {
        "ready": not missing,
        "mode": "controlled_production_canary" if not missing else "not_ready",
        "missing_controls": missing,
        "limits": [
            "Production proof is never implied by local, mock, or sandbox proof packs.",
            "Production proof requires explicit customer approval, canary-only execution, rollback planning, maintenance-window discipline, and provider readback.",
        ],
    }


def assess_compliance_posture(
    *, requested_frameworks: Iterable[str], has_external_audit: bool
) -> Dict[str, Any]:
    frameworks = [
        str(item).strip() for item in requested_frameworks or [] if str(item).strip()
    ]
    certified = bool(has_external_audit)
    return {
        "ok": True,
        "frameworks": frameworks,
        "certified": certified,
        "posture": "externally_attested" if certified else "technical_evidence_only",
        "evidence_artifacts": [
            "Security Receipts",
            "hash-chain audit verification",
            "proof-suite run summaries",
            "provider proof-pack limitations",
            "non-production pilot runbooks",
        ],
        "missing_for_certification": (
            []
            if certified
            else [
                "external auditor attestation",
                "documented control owner review",
                "formal policy/process evidence",
                "customer-specific deployment evidence",
            ]
        ),
        "limits": [
            "Technical evidence is not a certification unless an external audit or customer control review says so.",
            "Framework mapping should be treated as readiness support, not a compliance claim.",
        ],
    }
