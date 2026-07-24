"""Offline, corpus-bound Detection Quality Evidence generation.

This module deliberately reuses Interlock's existing surface-drift and
effective-permission evaluation functions. It does not implement a detector.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal, Union
from urllib.parse import unquote_plus, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.effective_permission import (
    evaluate_effective_permission_probe,
    normalize_observed_result,
)
from core.mcp_drift import classify_tool_drift
from core.tool_metadata import normalize_tool_metadata

EVIDENCE_FORMAT_VERSION = "1.0.0"
CORPUS_PATH = (
    Path(__file__).resolve().parents[1]
    / "evidence"
    / "detection_quality"
    / "v1"
    / "corpus.json"
)

# Evidence references must survive reformatting of the file they point at.
# A `path/to/test_file.py::test_name` identifier does; a `#L120` anchor does
# not, because any formatter shifts it silently onto an unrelated line.
TEST_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9_./-]+\.py::[A-Za-z_][A-Za-z0-9_]*")
LINE_ANCHOR_PATTERN = re.compile(r"#L\d+(?:-L?\d+)?$")

GroundTruth = Literal["drift", "no_drift", "inconclusive", "unsupported"]
Decision = Literal[
    "allow", "monitor", "deny", "quarantine", "inconclusive", "unsupported"
]
ResultCategory = Literal[
    "confirmed_drift",
    "confirmed_no_drift",
    "inconclusive",
    "known_miss",
    "unsupported_or_unscored",
]

ConfusionClass = Literal[
    "true_positive",
    "false_positive",
    "true_negative",
    "false_negative",
    "inconclusive",
    "unsupported_unscored",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


class SchemaField(StrictModel):
    type: Literal["string", "boolean", "number", "integer", "object", "array"]


class ObjectSchema(StrictModel):
    type: Literal["object"]
    properties: dict[str, SchemaField] = Field(min_length=1)
    required: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def required_fields_exist(self) -> "ObjectSchema":
        unknown = sorted(set(self.required) - set(self.properties))
        if unknown:
            raise ValueError(f"required fields missing from properties: {unknown}")
        return self


class McpAnnotations(StrictModel):
    read_only_hint: bool | None = Field(default=None, alias="readOnlyHint")
    destructive_hint: bool | None = Field(default=None, alias="destructiveHint")
    idempotent_hint: bool | None = Field(default=None, alias="idempotentHint")
    open_world_hint: bool | None = Field(default=None, alias="openWorldHint")


class ToolDefinition(StrictModel):
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    input_schema: ObjectSchema = Field(alias="inputSchema")
    output_schema: ObjectSchema | None = Field(default=None, alias="outputSchema")
    title: str | None = Field(default=None, min_length=1)
    annotations: McpAnnotations | None = None


class StoredMetadata(StrictModel):
    effects: list[str] = Field(min_length=1)
    side_effect: Literal["read_only", "mutating", "destructive", "unknown"]
    data_classes: list[str]
    externality: Literal["internal", "external", "unknown"]
    identity_mode: Literal[
        "unknown", "authenticated_user", "delegated_agent", "service_account"
    ]
    required_scopes: list[str]
    verification_level: Literal[
        "unknown", "heuristic", "mcp_annotations", "security_meta", "interlock_meta"
    ]
    confidence: float = Field(ge=0, le=1)
    warnings: list[str]


class SurfaceSnapshot(StrictModel):
    tool: ToolDefinition
    metadata: StoredMetadata | None = None
    synthetic_behavioral_change: str | None = None


class ProbeBaseline(StrictModel):
    expected_outcome: Literal["denied", "allowed"]
    manifest_fingerprint: str = Field(min_length=1, pattern=r"^[A-Za-z0-9._-]+$")


class ProbeObservation(StrictModel):
    status_code: int | None = Field(default=None, ge=100, le=599)
    body_kind: Literal["result", "denial", "malformed", "empty"]
    error_class: Literal["", "timeout", "network_error", "rate_limited"] = ""
    manifest_fingerprint: str = Field(min_length=1, pattern=r"^[A-Za-z0-9._-]+$")

    @model_validator(mode="after")
    def valid_observation_shape(self) -> "ProbeObservation":
        if self.error_class:
            if self.status_code is not None or self.body_kind != "empty":
                raise ValueError(
                    "error observations require status_code=null and body_kind=empty"
                )
        elif self.body_kind == "result" and self.status_code not in {
            200,
            201,
            202,
            204,
        }:
            raise ValueError("result observations require a successful status code")
        elif self.body_kind == "denial" and self.status_code not in {401, 403}:
            raise ValueError("denial observations require 401 or 403")
        elif self.body_kind == "empty" and self.status_code is None:
            raise ValueError("empty observations require a status code or error_class")
        return self


class CorpusCaseBase(StrictModel):
    case_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    expected_ground_truth_label: GroundTruth
    expected_interlock_decision: Decision
    rationale: str = Field(min_length=1)
    source_ref: str = ""
    source_url: str = ""
    known_blind_spot: bool = False
    inconclusive_reason: str = ""

    @field_validator("source_url")
    @classmethod
    def source_url_is_a_complete_web_url(cls, value: str) -> str:
        """Validate the source URL as a URL, not as free text.

        Corpus source links are parsed here so that the free-text scanner never
        has to guess whether a `/`-bearing string is a URL path or a filesystem
        path. Anything that is not a complete http(s) URL is rejected outright,
        and its query/fragment values get the same payload scan that inline
        URLs receive.
        """
        if not value:
            return value
        if not is_complete_web_url(value):
            raise ValueError(
                "source_url must be a complete http(s) URL without credentials"
            )
        if LINE_ANCHOR_PATTERN.search(value):
            raise ValueError(
                "source_url must not pin a #L line anchor; line numbers move "
                "whenever the referenced file is reformatted. Use the stable "
                "path::test_name identifier in source_ref instead."
            )
        assert_web_url_payload_safe(value, "source_url")
        return value

    @model_validator(mode="after")
    def validate_semantics(self) -> "CorpusCaseBase":
        if self.expected_ground_truth_label == "inconclusive":
            if self.expected_interlock_decision != "inconclusive":
                raise ValueError(
                    "inconclusive ground truth requires inconclusive decision"
                )
            if not self.inconclusive_reason:
                raise ValueError("inconclusive cases require inconclusive_reason")
        if self.known_blind_spot:
            # An unresolved blind spot is the strongest claim this corpus makes,
            # so its evidence reference must survive reformatting: a stable test
            # identifier plus a plain public file URL, never a line number.
            if not (self.source_ref and self.source_url):
                raise ValueError("blind spots require source_ref and source_url")
            if not TEST_IDENTIFIER_PATTERN.fullmatch(self.source_ref):
                raise ValueError(
                    "blind spot source_ref must be a stable test identifier of "
                    f"the form path/to/test_file.py::test_name, got {self.source_ref!r}"
                )
        _assert_safe_value(self.model_dump(mode="json", by_alias=True), "corpus case")
        return self


class SurfaceDriftCase(CorpusCaseBase):
    detector_path: Literal["surface_drift"]
    baseline: SurfaceSnapshot
    observed: SurfaceSnapshot


class EffectivePermissionCase(CorpusCaseBase):
    detector_path: Literal["effective_permission"]
    baseline: ProbeBaseline
    observed: ProbeObservation

    @model_validator(mode="after")
    def manifest_is_unchanged(self) -> "EffectivePermissionCase":
        if self.baseline.manifest_fingerprint != self.observed.manifest_fingerprint:
            raise ValueError(
                "effective-permission cases require unchanged manifest_fingerprint"
            )
        return self


CorpusCase = Annotated[
    Union[SurfaceDriftCase, EffectivePermissionCase],
    Field(discriminator="detector_path"),
]


class Corpus(StrictModel):
    corpus_version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    cases: list[CorpusCase] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_case_ids(self) -> "Corpus":
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("corpus case IDs must be unique")
        return self


class DetectorEvidence(StrictModel):
    severity: str
    action: str
    finding_types: list[str]
    observed_outcome: str = ""
    observed_error_class: str = ""


class CaseResult(StrictModel):
    case_id: str
    category: str
    detector_path: str
    ground_truth_label: GroundTruth
    expected_interlock_decision: Decision
    actual_interlock_decision: Decision
    confusion_class: ConfusionClass
    result_category: ResultCategory
    positive_prediction: bool
    matches_expected_decision: bool
    input_fingerprint_sha256: str
    rationale: str
    source_ref: str
    source_url: str
    known_blind_spot: bool
    inconclusive_reason: str
    detector_evidence: DetectorEvidence


class RatioMetric(StrictModel):
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    value: float | None
    qualification: Literal["corpus-bound"] = "corpus-bound"


class AggregateMetrics(StrictModel):
    total_corpus_case_count: int = Field(ge=0)
    evaluated_case_count: int = Field(ge=0)
    confirmed_true_positives: int = Field(ge=0)
    confirmed_false_positives: int = Field(ge=0)
    confirmed_true_negatives: int = Field(ge=0)
    confirmed_false_negatives_or_known_misses: int = Field(ge=0)
    known_miss_count: int = Field(ge=0)
    inconclusive_count: int = Field(ge=0)
    unsupported_or_unscored_count: int = Field(ge=0)
    corpus_bound_precision: RatioMetric
    corpus_bound_recall: RatioMetric
    corpus_bound_false_positive_rate: RatioMetric
    inconclusive_by_reason: dict[str, int]


class BlindSpot(StrictModel):
    case_id: str
    source_ref: str
    source_url: str
    ground_truth_label: GroundTruth
    actual_interlock_decision: Decision
    rationale: str


class InterlockBuild(StrictModel):
    revision: str
    dirty_diff_sha256: str
    version: str


class EvidenceReport(StrictModel):
    evidence_format_version: str
    corpus_version: str
    corpus_sha256: str
    interlock: InterlockBuild
    generated_at_utc: str
    scope: str
    cases: list[CaseResult]
    aggregate_metrics: AggregateMetrics
    unresolved_blind_spots: list[BlindSpot]
    limitations: list[str]


class EvidenceError(RuntimeError):
    """Raised when evidence cannot be produced safely and reproducibly."""


def load_corpus(path: Path = CORPUS_PATH) -> Corpus:
    raw = json.loads(path.read_text(encoding="utf-8"))
    corpus = Corpus.model_validate(raw)
    _assert_safe_value(raw, "corpus")
    return corpus


def corpus_sha256(corpus: Corpus) -> str:
    return hashlib.sha256(_canonical_json(corpus.model_dump()).encode()).hexdigest()


def evaluate_case(case: SurfaceDriftCase | EffectivePermissionCase) -> CaseResult:
    if case.detector_path == "surface_drift":
        decision, evidence = _evaluate_surface_case(case)
    else:
        decision, evidence = _evaluate_effective_permission_case(case)

    positive = decision in {"deny", "quarantine"}
    confusion = _confusion_class(case.expected_ground_truth_label, positive)
    category = _result_category(confusion)
    fingerprint = hashlib.sha256(
        _canonical_json(
            {
                "baseline": case.baseline.model_dump(mode="json", by_alias=True),
                "observed": case.observed.model_dump(mode="json", by_alias=True),
            }
        ).encode()
    ).hexdigest()
    return CaseResult(
        case_id=case.case_id,
        category=case.category,
        detector_path=case.detector_path,
        ground_truth_label=case.expected_ground_truth_label,
        expected_interlock_decision=case.expected_interlock_decision,
        actual_interlock_decision=decision,
        confusion_class=confusion,
        result_category=category,
        positive_prediction=positive,
        matches_expected_decision=decision == case.expected_interlock_decision,
        input_fingerprint_sha256=fingerprint,
        rationale=case.rationale,
        source_ref=case.source_ref,
        source_url=case.source_url,
        known_blind_spot=case.known_blind_spot,
        inconclusive_reason=case.inconclusive_reason,
        detector_evidence=evidence,
    )


def score_results(
    results: list[CaseResult], *, require_valid_denominators: bool = False
) -> AggregateMetrics:
    true_positives = sum(
        result.confusion_class == "true_positive" for result in results
    )
    false_negatives = sum(
        result.confusion_class == "false_negative" for result in results
    )
    false_positives = sum(
        result.confusion_class == "false_positive" for result in results
    )
    true_negatives = sum(
        result.confusion_class == "true_negative" for result in results
    )
    precision = _ratio(true_positives, true_positives + false_positives)
    recall = _ratio(true_positives, true_positives + false_negatives)
    false_positive_rate = _ratio(false_positives, false_positives + true_negatives)
    if require_valid_denominators:
        invalid = [
            name
            for name, metric in (
                ("precision", precision),
                ("recall", recall),
                ("false-positive rate", false_positive_rate),
            )
            if metric.denominator == 0
        ]
        if invalid:
            raise EvidenceError(
                "invalid zero metric denominator(s): " + ", ".join(invalid)
            )

    inconclusive_reasons = Counter(
        result.inconclusive_reason
        for result in results
        if result.result_category == "inconclusive"
    )
    return AggregateMetrics(
        total_corpus_case_count=len(results),
        evaluated_case_count=sum(
            result.confusion_class != "unsupported_unscored" for result in results
        ),
        confirmed_true_positives=true_positives,
        confirmed_false_positives=false_positives,
        confirmed_true_negatives=true_negatives,
        confirmed_false_negatives_or_known_misses=false_negatives,
        known_miss_count=sum(
            result.result_category == "known_miss" for result in results
        ),
        inconclusive_count=sum(
            result.result_category == "inconclusive" for result in results
        ),
        unsupported_or_unscored_count=sum(
            result.confusion_class == "unsupported_unscored" for result in results
        ),
        corpus_bound_precision=precision,
        corpus_bound_recall=recall,
        corpus_bound_false_positive_rate=false_positive_rate,
        inconclusive_by_reason=dict(sorted(inconclusive_reasons.items())),
    )


def build_report(
    corpus: Corpus,
    *,
    generated_at_utc: str | None = None,
    revision: str | None = None,
    dirty_diff_sha256: str | None = None,
    version: str | None = None,
) -> EvidenceReport:
    results = [evaluate_case(case) for case in corpus.cases]
    mismatches = [
        result.case_id for result in results if not result.matches_expected_decision
    ]
    if mismatches:
        raise EvidenceError(
            "expected Interlock decision changed for case(s): " + ", ".join(mismatches)
        )

    report = EvidenceReport(
        evidence_format_version=EVIDENCE_FORMAT_VERSION,
        corpus_version=corpus.corpus_version,
        corpus_sha256=corpus_sha256(corpus),
        interlock=_interlock_build(revision, dirty_diff_sha256, version),
        generated_at_utc=generated_at_utc or _utc_now(),
        scope="corpus-bound synthetic detection-quality evidence",
        cases=results,
        aggregate_metrics=score_results(results, require_valid_denominators=True),
        unresolved_blind_spots=[
            BlindSpot(
                case_id=result.case_id,
                source_ref=result.source_ref,
                source_url=result.source_url,
                ground_truth_label=result.ground_truth_label,
                actual_interlock_decision=result.actual_interlock_decision,
                rationale=result.rationale,
            )
            for result in results
            if result.known_blind_spot and result.result_category == "known_miss"
        ],
        limitations=[
            "This report is corpus-bound and uses only synthetic fixtures.",
            "It is not a production false-positive rate.",
            "It is not representative of all MCP deployments.",
            "It uses no production telemetry, live customer data, or live upstream calls.",
            "A passing report proves only that the named corpus produced its reviewed expected decisions at this Interlock revision.",
        ],
    )
    EvidenceReport.model_validate(report.model_dump())
    assert_report_safe(report)
    return report


def write_report(
    report: EvidenceReport, output_dir: Path | None = None
) -> tuple[Path, Path]:
    target = output_dir or Path(tempfile.mkdtemp(prefix="interlock-dq-evidence-"))
    target.mkdir(parents=True, exist_ok=True)
    if not target.is_dir():
        raise EvidenceError(f"output path is not a directory: {target}")
    json_path = target / "detection-quality-evidence.v1.json"
    markdown_path = target / "detection-quality-evidence.v1.md"
    json_path.write_text(render_json(report), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path.resolve(), markdown_path.resolve()


def render_json(report: EvidenceReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def render_markdown(report: EvidenceReport) -> str:
    metrics = report.aggregate_metrics
    lines = [
        "# Interlock Detection Quality Evidence v1",
        "",
        f"- Evidence format: `{report.evidence_format_version}`",
        f"- Corpus: `{report.corpus_version}` (`sha256:{report.corpus_sha256}`)",
        f"- Interlock revision: `{report.interlock.revision}`",
        f"- Tracked dirty diff SHA-256: `{report.interlock.dirty_diff_sha256 or 'clean'}`",
        f"- Interlock version: `{report.interlock.version}`",
        f"- Generated at: `{report.generated_at_utc}`",
        "- Scope: **corpus-bound synthetic detection-quality evidence**",
        "",
        "## Aggregate metrics",
        "",
        f"- Total corpus cases: {metrics.total_corpus_case_count}",
        f"- Evaluated cases: {metrics.evaluated_case_count}",
        f"- Confirmed true positives: {metrics.confirmed_true_positives}",
        f"- Confirmed false positives: {metrics.confirmed_false_positives}",
        f"- Confirmed true negatives: {metrics.confirmed_true_negatives}",
        f"- Confirmed false negatives: {metrics.confirmed_false_negatives_or_known_misses}",
        f"- Total known-miss cases (false negatives + false positives): {metrics.known_miss_count}",
        f"- Inconclusive: {metrics.inconclusive_count}",
        f"- Unsupported or unscored: {metrics.unsupported_or_unscored_count}",
        "- Corpus-bound precision: " + _format_ratio(metrics.corpus_bound_precision),
        "- Corpus-bound recall: " + _format_ratio(metrics.corpus_bound_recall),
        "- Corpus-bound false-positive rate over labeled no-drift controls: "
        + _format_ratio(metrics.corpus_bound_false_positive_rate),
        "",
        "### Inconclusive by reason",
        "",
    ]
    if metrics.inconclusive_by_reason:
        lines.extend(
            f"- `{reason}`: {count}"
            for reason, count in metrics.inconclusive_by_reason.items()
        )
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Per-case results",
            "",
            "| Case | Category | Ground truth | Interlock decision | Confusion class | Result | Source |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for result in report.cases:
        source = (
            f"[{result.source_ref}]({result.source_url})" if result.source_url else "-"
        )
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{result.case_id}`",
                    result.category,
                    result.ground_truth_label,
                    result.actual_interlock_decision,
                    result.confusion_class,
                    result.result_category,
                    source,
                )
            )
            + " |"
        )

    lines.extend(["", "## Unresolved blind spots", ""])
    if report.unresolved_blind_spots:
        for blind_spot in report.unresolved_blind_spots:
            lines.append(
                f"- `{blind_spot.case_id}`: {blind_spot.rationale} "
                f"[{blind_spot.source_ref}]({blind_spot.source_url})"
            )
    else:
        lines.append("- None in this corpus.")

    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def assert_report_safe(report: EvidenceReport | dict[str, Any]) -> None:
    raw = (
        report.model_dump(mode="json") if isinstance(report, EvidenceReport) else report
    )

    _assert_safe_value(raw, "report")


def _evaluate_surface_case(case: SurfaceDriftCase) -> tuple[Decision, DetectorEvidence]:
    previous_tool = case.baseline.tool.model_dump(by_alias=True, exclude_none=True)
    current_tool = case.observed.tool.model_dump(by_alias=True, exclude_none=True)
    previous_metadata = (
        case.baseline.metadata.model_dump() if case.baseline.metadata else None
    )
    current_metadata = (
        case.observed.metadata.model_dump() if case.observed.metadata else None
    )
    if previous_metadata is None:
        previous_metadata = normalize_tool_metadata(previous_tool)
    if current_metadata is None:
        current_metadata = normalize_tool_metadata(current_tool)
    result = classify_tool_drift(
        previous_tool,
        current_tool,
        dict(previous_metadata),
        dict(current_metadata),
    )
    decision = str(result["action"])
    return _as_decision(decision), DetectorEvidence(
        severity=str(result.get("severity") or "none"),
        action=decision,
        finding_types=[str(value) for value in result.get("types") or []],
    )


def _evaluate_effective_permission_case(
    case: EffectivePermissionCase,
) -> tuple[Decision, DetectorEvidence]:
    body_kind = case.observed.body_kind
    json_body: dict[str, Any] | None
    if body_kind == "result":
        json_body = {"result": {"synthetic": True}}
    elif body_kind == "denial":
        json_body = {"error": {"message": "synthetic access denied", "status": 403}}
    elif body_kind == "malformed":
        json_body = None
    elif body_kind == "empty":
        json_body = {}
    else:
        raise EvidenceError(f"unsupported body_kind in {case.case_id}: {body_kind}")

    observed = normalize_observed_result(
        status_code=case.observed.status_code,
        json_body=json_body,
        error_class=case.observed.error_class,
    )
    evaluation = evaluate_effective_permission_probe(
        {
            "probe_id": case.case_id,
            "server_id": "synthetic-server",
            "tool_name": "synthetic_tool",
            "argument_hash": "synthetic-fixture-hash",
            "expected_outcome": case.baseline.expected_outcome,
        },
        observed,
    )
    observed_outcome = str(evaluation.get("observed_outcome") or "unknown")
    decision: Decision = (
        "inconclusive"
        if observed_outcome == "unknown" or observed_outcome.startswith("inconclusive")
        else _as_decision(str(evaluation.get("decision") or "monitor"))
    )
    return decision, DetectorEvidence(
        severity=str(evaluation.get("severity") or "none"),
        action=str(evaluation.get("decision") or "monitor"),
        finding_types=[str(value) for value in evaluation.get("finding_types") or []],
        observed_outcome=observed_outcome,
        observed_error_class=str(evaluation.get("observed_error_class") or ""),
    )


def _confusion_class(ground_truth: GroundTruth, positive: bool) -> ConfusionClass:
    if ground_truth == "unsupported":
        return "unsupported_unscored"
    if ground_truth == "inconclusive":
        return "inconclusive"
    if ground_truth == "drift":
        return "true_positive" if positive else "false_negative"
    return "false_positive" if positive else "true_negative"


def _result_category(confusion: ConfusionClass) -> ResultCategory:
    if confusion == "unsupported_unscored":
        return "unsupported_or_unscored"
    if confusion == "inconclusive":
        return "inconclusive"
    if confusion == "true_positive":
        return "confirmed_drift"
    if confusion == "true_negative":
        return "confirmed_no_drift"
    return "known_miss"


def _ratio(numerator: int, denominator: int) -> RatioMetric:
    value = round(numerator / denominator, 6) if denominator else None
    return RatioMetric(numerator=numerator, denominator=denominator, value=value)


def _format_ratio(metric: RatioMetric) -> str:
    value = "not defined" if metric.value is None else f"{metric.value:.6f}"
    return f"{value} ({metric.numerator}/{metric.denominator}, corpus-bound)"


def _as_decision(value: str) -> Decision:
    if value not in {
        "allow",
        "monitor",
        "deny",
        "quarantine",
        "inconclusive",
        "unsupported",
    }:
        raise EvidenceError(f"unsupported Interlock decision: {value}")
    return value  # type: ignore[return-value]


FORBIDDEN_KEY_TOKENS = (
    "authorization",
    "apikey",
    "accesstoken",
    "secret",
    "password",
    "credential",
    "privatekey",
    "cookie",
    "headers",
    "arguments",
    "requestbody",
    "responsebody",
    "rawbody",
    "jsonbody",
)
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+"),
    # Common opaque provider tokens. These are deliberately specific; the
    # evidence boundary does not claim to identify arbitrary base64 text.
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    # Bare vendor-style secret prefix.
    re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{4,}"),
    # Same prefix glued to a preceding word ("mysk-proj-..."). Bounded to known
    # vendor tags so ordinary hyphenated words ("risk-based") do not match.
    re.compile(r"(?i)sk-(?:proj|live|test|ant|svcacct|or)[_-][A-Za-z0-9_-]{4,}"),
    # Glued opaque key: requires length AND at least one digit, which excludes
    # prose compounds while still catching pasted keys.
    re.compile(r"(?i)sk-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{12,}"),
    # JWT-shaped value. `eyJ` is base64 of `{"` and is deliberately
    # case-sensitive; segment floors are low enough to reject truncated
    # variants but still require the three-segment dotted shape.
    re.compile(r"\beyJ[A-Za-z0-9_-]{1,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\b"),
    re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(?:api[_ -]?key|access[_ -]?token|secret(?:[_ -]?key)?|password)\s*[:=]\s*\S+"
    ),
    re.compile(r"(?i)\b(?:set-?cookie|cookie)\s*[:=]"),
    # URL userinfo credentials ("https://user:pass@host/..."). Rejecting the
    # URL as non-strippable is not enough on its own, because a credential URL
    # left in residual text matches no filesystem-path rule. A host:port
    # authority has no `@` and is unaffected.
    re.compile(r"(?i)\bhttps?://[^\s/@]+(?::[^\s/@]*)?@"),
)

# `file://` is forbidden everywhere and is never treated as a strippable URL.
FILE_URI_PATTERN = re.compile(r"(?i)\bfile://")

# Well-known absolute roots, matched anywhere so that a path glued to a
# preceding word ("seefile/etc/passwd") cannot evade detection.
_ABSOLUTE_ROOTS = (
    "etc|var|usr|home|root|tmp|opt|proc|sys|dev|mnt|media|srv|boot|bin|sbin|lib"
    "|users|volumes|library|applications|private|windows|programdata"
)
UNSAFE_PATH_PATTERNS = (
    # Windows drive + backslash, anywhere, including glued ("fromC:\\...").
    # Backslash form cannot collide with a URL authority separator.
    re.compile(r"[A-Za-z]:\\"),
    # Windows drive + forward slash. The lookbehind rejects a glued
    # alphanumeric so that the `s:/` inside `https://` is not a drive letter,
    # while `src:C:/...` and bare `C:/...` still match.
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:/"),
    # Windows drive-relative path. Require a single-letter drive at a token
    # boundary, so `C:Customers` and `capture=C:folder/file` fail closed while
    # ordinary prose such as `abc:example` is not classified as a path.
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:(?=[A-Za-z0-9._~-])"),
    # UNC prefix, anywhere.
    re.compile(r"\\\\"),
    # Forward-slash UNC. The explicit colon guard keeps the authority
    # separator in `https://` and `http://` from being mistaken for UNC.
    re.compile(r"(?<!:)(?<![A-Za-z0-9._-])//[A-Za-z0-9._-]+/[A-Za-z0-9._~-]+"),
    # Any token-bound POSIX absolute path, including a single arbitrary root
    # such as `/secrets`. Complete public http(s) URL tokens are removed before
    # this scanner runs, so their URL path components remain valid.
    re.compile(r"(?<![A-Za-z0-9._~/-])/(?!/)[A-Za-z0-9._~-]+"),
    # POSIX absolute path with at least two segments. The lookbehind excludes
    # path characters only, so `capture=/etc/passwd`, `path:/var/lib/x` and
    # `dump>/var/lib/x` match while relative repo paths ("tests/test_x.py")
    # do not.
    re.compile(r"(?<![A-Za-z0-9._~/-])/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]*)+"),
    # Well-known absolute root anywhere, covering glued and single-segment
    # forms that the structural rule above intentionally skips.
    re.compile(rf"(?i)/(?:{_ABSOLUTE_ROOTS})(?:/|\b)"),
)

# A complete web URL token. Backslash is excluded so a Windows path appended to
# a URL cannot be swallowed into the token and thereby exempted.
_WEB_URL_CANDIDATE = re.compile(r"(?i)\bhttps?://[^\s<>\"'\\]+")


# Percent-encoding can be layered, so decoding is repeated to a bounded depth
# rather than once. The bound keeps a hostile input from driving unbounded work.
MAX_URL_DECODE_DEPTH = 3


def is_complete_web_url(candidate: str) -> bool:
    """True only for a complete, credential-free http(s) URL."""
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and "@" not in parsed.netloc
        and not any(character.isspace() for character in candidate)
    )


def _decoded_variants(raw: str) -> tuple[str, ...]:
    """Every percent-decoding of `raw` up to `MAX_URL_DECODE_DEPTH`."""
    variants = [raw]
    current = raw
    for _ in range(MAX_URL_DECODE_DEPTH):
        decoded = unquote_plus(current)
        if decoded == current:
            break
        variants.append(decoded)
        current = decoded
    return tuple(variants)


def _find_unsafe_text(text: str) -> str | None:
    """Return a reason string if `text` carries credential or path content."""
    if any(pattern.search(text) for pattern in SENSITIVE_VALUE_PATTERNS):
        return "forbidden sensitive value"
    if FILE_URI_PATTERN.search(text):
        return "unsafe filesystem path"
    if any(pattern.search(text) for pattern in UNSAFE_PATH_PATTERNS):
        return "unsafe filesystem path"
    return None


def assert_web_url_payload_safe(url: str, path: str = "url") -> None:
    """Reject a complete web URL that smuggles unsafe content.

    The URL *path* component is public web routing and stays allowed:
    `https://example.com/etc/passwd` is a URL path, not a local filesystem
    path. Query and fragment values are different — they are ordinary carriers
    for arbitrary data, so they are recursively percent-decoded to a bounded
    depth and scanned with the same credential and filesystem-path rules used
    for free text.
    """
    parsed = urlsplit(url)
    for label, raw in (("query", parsed.query), ("fragment", parsed.fragment)):
        if not raw:
            continue
        for decoded in _decoded_variants(raw):
            reason = _find_unsafe_text(decoded)
            if reason:
                raise EvidenceError(f"{reason} in URL {label} at {path}")


def _strip_complete_web_urls(text: str, path: str) -> str:
    """Remove only well-formed, payload-safe http(s) URL tokens.

    This is deliberately not a blanket exemption: a string is not trusted
    because it contains `https://`. Each candidate token is parsed and
    validated on its own; anything that fails validation stays in the residual
    text that the filesystem-path scanner then inspects, and a complete URL
    whose query or fragment hides unsafe content fails the whole input.
    """

    def replace(match: "re.Match[str]") -> str:
        token = match.group(0)
        if match.string[match.end() : match.end() + 1] == "\\":
            # The token charset stops at a backslash, so this URL was truncated
            # by a Windows/UNC path glued onto it. Leave the whole token in the
            # residual text instead of exempting a partial URL, so the
            # filesystem-path scanner still sees the drive or UNC prefix.
            return token
        if not is_complete_web_url(token):
            return token
        assert_web_url_payload_safe(token, path)
        return " "

    return _WEB_URL_CANDIDATE.sub(replace, text)


def _assert_safe_value(value: Any, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized == "token" or any(
                token in normalized for token in FORBIDDEN_KEY_TOKENS
            ):
                raise EvidenceError(f"forbidden sensitive field at {path}.{key}")
            _assert_safe_value(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_safe_value(child, f"{path}[{index}]")
    elif isinstance(value, str):
        # Credential scanning always sees the complete string, including any
        # URL, so a secret embedded in a query string is still caught.
        if any(pattern.search(value) for pattern in SENSITIVE_VALUE_PATTERNS):
            raise EvidenceError(f"forbidden sensitive value at {path}")
        if FILE_URI_PATTERN.search(value):
            raise EvidenceError(f"unsafe filesystem path at {path}")
        residual = _strip_complete_web_urls(value, path)
        if any(pattern.search(residual) for pattern in UNSAFE_PATH_PATTERNS):
            raise EvidenceError(f"unsafe filesystem path at {path}")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _interlock_build(
    revision: str | None, dirty_diff_sha256: str | None, version: str | None
) -> InterlockBuild:
    if revision is not None:
        return InterlockBuild(
            revision=revision,
            dirty_diff_sha256=dirty_diff_sha256 or "",
            version=version if version is not None else _project_version(),
        )
    current_revision, current_dirty_diff = _git_revision_identity()
    return InterlockBuild(
        revision=current_revision,
        dirty_diff_sha256=current_dirty_diff,
        version=version if version is not None else _project_version(),
    )


def _git_revision_identity(repo_root: Path | None = None) -> tuple[str, str]:
    root = repo_root or Path(__file__).resolve().parents[1]
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        diff = subprocess.run(
            ["git", "diff", "--binary", "--no-ext-diff", "HEAD", "--"],
            cwd=root,
            check=True,
            capture_output=True,
            timeout=5,
        ).stdout
        if not diff:
            return revision, ""
        return revision, hashlib.sha256(diff).hexdigest()
    except (OSError, subprocess.SubprocessError):
        return "unavailable", ""


def _project_version() -> str:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("version ="):
            return line.split("=", 1)[1].strip().strip('"')
    return "unavailable"
