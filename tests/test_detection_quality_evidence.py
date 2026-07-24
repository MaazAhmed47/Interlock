"""Focused tests for offline Detection Quality Evidence v1."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import pytest
from pydantic import ValidationError

from core.detection_quality_evidence import (
    CORPUS_PATH,
    LINE_ANCHOR_PATTERN,
    MAX_URL_DECODE_DEPTH,
    TEST_IDENTIFIER_PATTERN,
    AggregateMetrics,
    Corpus,
    EvidenceError,
    EvidenceReport,
    assert_report_safe,
    assert_web_url_payload_safe,
    build_report,
    _assert_safe_value,
    _decoded_variants,
    _git_revision_identity,
    is_complete_web_url,
    load_corpus,
    render_json,
    render_markdown,
    score_results,
)

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "generate_detection_quality_evidence.py"
EXPECTED_GAPS = {
    "DQV1-GAP-FN1",
    "DQV1-GAP-FN5",
    "DQV1-GAP-FN7",
    "DQV1-GAP-FN10",
    "DQV1-GAP-FP2",
    "DQV1-GAP-HM1",
    "DQV1-GAP-HM3",
}


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    return load_corpus()


@pytest.fixture(scope="module")
def report(corpus: Corpus) -> EvidenceReport:
    return build_report(
        corpus,
        generated_at_utc="2026-01-01T00:00:00Z",
        revision="synthetic-revision",
        version="test-version",
    )


def test_corpus_is_strict_valid_versioned_and_uniquely_identified(
    corpus: Corpus,
) -> None:
    assert corpus.corpus_version == "1.0.0"
    case_ids = [case.case_id for case in corpus.cases]
    assert len(case_ids) == len(set(case_ids)) == 15
    assert all(case.rationale for case in corpus.cases)
    assert all(case.expected_ground_truth_label for case in corpus.cases)

    raw = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Corpus.model_validate(raw)


def test_corpus_rejects_duplicate_ids_and_missing_labels(corpus: Corpus) -> None:
    raw = corpus.model_dump()
    raw["cases"][1]["case_id"] = raw["cases"][0]["case_id"]
    with pytest.raises(ValidationError, match="case IDs must be unique"):
        Corpus.model_validate(raw)

    raw = corpus.model_dump()
    del raw["cases"][0]["expected_ground_truth_label"]
    with pytest.raises(ValidationError, match="expected_ground_truth_label"):
        Corpus.model_validate(raw)


def test_corpus_rejects_empty_detector_inputs_and_invalid_probe_shapes(
    corpus: Corpus,
) -> None:
    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["baseline"] = {}
    with pytest.raises(ValidationError, match="tool"):
        Corpus.model_validate(raw)

    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][1]["observed"]["body_kind"] = "denial"
    with pytest.raises(ValidationError, match="denial observations require"):
        Corpus.model_validate(raw)

    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["detector_path"] = "invented_detector"
    with pytest.raises(ValidationError, match="union_tag_invalid"):
        Corpus.model_validate(raw)


def test_report_exercises_existing_surface_and_probe_paths(
    report: EvidenceReport,
) -> None:
    by_id = {result.case_id: result for result in report.cases}
    declared = by_id["DQV1-SURFACE-001"]
    assert declared.actual_interlock_decision == "quarantine"
    assert declared.detector_evidence.severity == "critical"
    assert "effect_escalated" in declared.detector_evidence.finding_types

    behavioral = by_id["DQV1-PROBE-001"]
    assert behavioral.actual_interlock_decision == "quarantine"
    assert behavioral.detector_evidence.observed_outcome == "allowed"
    assert (
        "effective_permission_expansion" in behavioral.detector_evidence.finding_types
    )

    clean = by_id["DQV1-PROBE-002"]
    assert clean.actual_interlock_decision == "allow"
    assert clean.detector_evidence.observed_outcome == "denied"


def test_scoring_math_and_denominators_are_explicit(
    report: EvidenceReport,
) -> None:
    metrics = report.aggregate_metrics
    assert metrics.evaluated_case_count == 15
    assert metrics.total_corpus_case_count == 15
    assert metrics.confirmed_true_positives == 3
    assert metrics.confirmed_false_positives == 3
    assert metrics.confirmed_true_negatives == 2
    assert metrics.confirmed_false_negatives_or_known_misses == 4
    assert metrics.corpus_bound_precision.model_dump() == {
        "numerator": 3,
        "denominator": 6,
        "value": 0.5,
        "qualification": "corpus-bound",
    }
    assert metrics.corpus_bound_recall.model_dump() == {
        "numerator": 3,
        "denominator": 7,
        "value": 0.428571,
        "qualification": "corpus-bound",
    }
    assert metrics.corpus_bound_false_positive_rate.model_dump() == {
        "numerator": 3,
        "denominator": 5,
        "value": 0.6,
        "qualification": "corpus-bound",
    }


def test_zero_denominators_are_unscored_and_gate_can_fail() -> None:
    metrics = score_results([])
    assert isinstance(metrics, AggregateMetrics)
    assert metrics.corpus_bound_precision.value is None
    assert metrics.corpus_bound_recall.value is None
    assert metrics.corpus_bound_false_positive_rate.value is None
    with pytest.raises(EvidenceError, match="invalid zero metric denominator"):
        score_results([], require_valid_denominators=True)


def test_inconclusive_cases_do_not_inflate_confusion_metrics(
    report: EvidenceReport,
) -> None:
    metrics = report.aggregate_metrics
    assert metrics.inconclusive_count == 3
    assert metrics.inconclusive_by_reason == {
        "rate_limited": 1,
        "timeout": 1,
        "upstream_error": 1,
    }
    assert (
        metrics.corpus_bound_recall.denominator
        + metrics.corpus_bound_false_positive_rate.denominator
        + metrics.inconclusive_count
        == metrics.evaluated_case_count
    )


def test_every_documented_unresolved_gap_is_visible_and_linked(
    report: EvidenceReport,
) -> None:
    blind_spots = {item.case_id: item for item in report.unresolved_blind_spots}
    assert set(blind_spots) == EXPECTED_GAPS
    assert all(item.source_ref and item.source_url for item in blind_spots.values())
    markdown = render_markdown(report)
    assert all(case_id in markdown for case_id in EXPECTED_GAPS)
    assert "DQV1-RESOLVED-FN2" in markdown
    assert "DQV1-RESOLVED-FN2" not in blind_spots


def test_every_confusion_class_is_explicit_in_json_and_markdown(
    corpus: Corpus, report: EvidenceReport
) -> None:
    current_classes = {case.confusion_class for case in report.cases}
    assert current_classes == {
        "true_positive",
        "false_positive",
        "true_negative",
        "false_negative",
        "inconclusive",
    }
    markdown = render_markdown(report)
    assert "Confusion class" in markdown
    for confusion_class in current_classes:
        assert confusion_class in markdown

    raw = corpus.model_dump(mode="json", by_alias=True)
    unsupported = json.loads(
        json.dumps(
            next(case for case in raw["cases"] if case["case_id"] == "DQV1-SAFE-001")
        )
    )
    unsupported["case_id"] = "DQV1-UNSUPPORTED-001"
    unsupported["expected_ground_truth_label"] = "unsupported"
    raw["cases"].append(unsupported)
    expanded = Corpus.model_validate(raw)
    expanded_report = build_report(
        expanded,
        generated_at_utc="2026-01-01T00:00:00Z",
        revision="synthetic-revision",
        version="test-version",
    )
    assert expanded_report.cases[-1].confusion_class == "unsupported_unscored"
    assert expanded_report.aggregate_metrics.total_corpus_case_count == 16
    assert expanded_report.aggregate_metrics.evaluated_case_count == 15
    assert expanded_report.aggregate_metrics.unsupported_or_unscored_count == 1


def test_report_is_deterministic_after_timestamp_and_revision_normalization(
    corpus: Corpus,
) -> None:
    first = build_report(
        corpus,
        generated_at_utc="2026-01-01T00:00:00Z",
        revision="revision-one",
        version="test-version",
    ).model_dump(mode="json")
    second = build_report(
        corpus,
        generated_at_utc="2026-01-02T00:00:00Z",
        revision="revision-two",
        version="test-version",
    ).model_dump(mode="json")
    for value in (first, second):
        value["generated_at_utc"] = "<normalized>"
        value["interlock"]["revision"] = "<normalized>"
        value["interlock"]["dirty_diff_sha256"] = "<normalized>"
    assert first == second


def test_dirty_revision_identity_hashes_complete_tracked_diff(tmp_path: Path) -> None:
    repo = tmp_path / "tracked-diff-repo"
    repo.mkdir()
    for command in (
        ["git", "init"],
        ["git", "config", "user.email", "evidence@example.invalid"],
        ["git", "config", "user.name", "Evidence Test"],
    ):
        subprocess.run(command, cwd=repo, check=True, capture_output=True, text=True)
    tracked = repo / "detector.py"
    tracked.write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "detector.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True)

    clean_revision, clean_digest = _git_revision_identity(repo)
    assert len(clean_revision) == 40
    assert clean_digest == ""

    tracked.write_text("detector edit one\n", encoding="utf-8")
    first_revision, first_digest = _git_revision_identity(repo)
    tracked.write_text("detector edit two\n", encoding="utf-8")
    second_revision, second_digest = _git_revision_identity(repo)
    assert first_revision == second_revision == clean_revision
    assert len(first_digest) == len(second_digest) == 64
    assert first_digest != second_digest


def test_output_is_strictly_typed_json_and_markdown(report: EvidenceReport) -> None:
    parsed = json.loads(render_json(report))
    assert EvidenceReport.model_validate(parsed) == report
    markdown = render_markdown(report)
    assert "corpus-bound" in markdown
    assert "synthetic" in markdown
    assert "not a production false-positive rate" in markdown
    assert "not representative of all MCP deployments" in markdown


def test_sensitive_fields_and_values_cannot_enter_report(
    report: EvidenceReport,
) -> None:
    rendered = render_json(report) + render_markdown(report)
    for marker in (
        "argument-secret-value",
        "super-secret-token",
        "Authorization: Bearer",
        "sk-live-",
    ):
        assert marker not in rendered
    assert_report_safe(report)
    with pytest.raises(EvidenceError, match="forbidden sensitive field"):
        assert_report_safe({"cases": [{"arguments": {"path": "synthetic"}}]})
    with pytest.raises(EvidenceError, match="forbidden sensitive value"):
        assert_report_safe({"note": "Authorization: Bearer synthetic-secret"})


# Every value reviewed in the hostile pass, bare and prefixed. Prefixed forms
# are the ones an anchored scanner used to miss, so they are pinned here.
REVIEWED_UNSAFE_VALUES = [
    # Windows drive paths: bare, CLI-style, log-style, glued.
    r"C:\Customers\Acme\case.json",
    r"capture=C:\Customers\Acme\case.json",
    r"src:C:\Customers\Acme\case.json",
    r"a,C:\Customers\Acme\case.json",
    r"fromC:\Customers\Acme\case.json",
    r"d:\customers\acme\case.json",
    "C:/Customers/Acme/case.json",
    "src:C:/Customers/Acme/case.json",
    # UNC paths.
    r"\\fileserver\share\case.json",
    r"src=\\fileserver\share\case.json",
    r"src:\\fileserver\share\case.json",
    # POSIX absolute paths: bare, CLI-style, log-style, redirect, glued.
    "/etc/passwd",
    "capture=/etc/passwd",
    "path:/etc/passwd",
    "a,/var/lib/interlock/data.db",
    "seefile/etc/passwd",
    "dump>/var/lib/secrets.db",
    "--input=/var/lib/interlock/customer.db",
    "path:/var/lib/interlock/customer.db",
    # file:// URIs are forbidden everywhere.
    "file:///C:/Acme/private.json",
    "u=file:///etc/shadow",
    "FILE:///etc/shadow",
    # Credential shapes.
    "Bearer abc123def456ghi",
    "Authorization:Bearer abc123def456",
    "sk-proj-AbCdEf123456",
    # Synthetic, non-functional fixtures. They exist to prove the sanitizer
    # rejects these shapes, so they must stay literal; gitleaks cannot tell a
    # deliberate fixture from a real key, hence the line-scoped allows.
    "key=sk-proj-AbCdEf123456",  # gitleaks:allow
    "mysk-proj-AbCdEf123456",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N",  # gitleaks:allow  # noqa: E501
    "eyJhbGciO.eyJzdWIiOA.dozjgNryX",
    "eyJhbGci.eyJzdWIi.dozjgNry",
    "eyJh.eyJz.dozj",
    "-----BEGIN PRIVATE KEY-----",
    "blob=-----BEGIN RSA PRIVATE KEY-----MIIE",
    "ghp_abcdefghijklmnopqrstuvwxyz123456",
    "github_pat_abcdefghijklmnopqrstuvwxyz_1234567890",
    "xoxb-1234567890-abcdefghij",
]


# These are intentionally arbitrary path shapes rather than an enumerated
# collection of familiar roots. Every class is exercised as free text, nested
# corpus data, URL query/fragment data, and through every documented decoding
# layer. This prevents a future anchored or root-list-only scanner regression.
LOCAL_PATH_CLASS_VALUES = {
    "posix_single_segment": "/secrets",
    "posix_single_segment_second_root": "/customerdata",
    "windows_drive_relative": "C:Customers",
    "windows_drive_relative_forward_slash": "C:folder/file",
    "windows_drive_rooted_backslash": r"C:\Customers\Acme\case.json",
    "windows_drive_rooted_forward_slash": "C:/Customers/Acme/case.json",
    "forward_slash_unc": "//fileserver/share/case.json",
}


def _encoded_path_payload(payload: str, depth: int) -> str:
    encoded = payload
    for _ in range(depth):
        encoded = quote(encoded, safe="")
    return encoded


# Nested string slots, so the scanner is proven to recurse rather than only
# inspect top-level case fields.
NESTED_SLOTS = {
    "rationale": lambda case, value: case.__setitem__("rationale", value),
    "category": lambda case, value: case.__setitem__("category", value),
    "tool.description": lambda case, value: case["baseline"]["tool"].__setitem__(
        "description", value
    ),
    "tool.name": lambda case, value: case["observed"]["tool"].__setitem__(
        "name", value
    ),
    "metadata.warnings[]": lambda case, value: case["baseline"]["metadata"][
        "warnings"
    ].append(value),
    "metadata.data_classes[0]": lambda case, value: case["baseline"]["metadata"][
        "data_classes"
    ].__setitem__(0, value),
    "metadata.required_scopes[0]": lambda case, value: case["baseline"]["metadata"][
        "required_scopes"
    ].__setitem__(0, value),
    "observed.synthetic_behavioral_change": lambda case, value: case[
        "observed"
    ].__setitem__("synthetic_behavioral_change", value),
}


@pytest.mark.parametrize("unsafe_value", REVIEWED_UNSAFE_VALUES)
def test_corpus_rejects_reviewed_sensitive_and_unsafe_bypasses(
    corpus: Corpus, unsafe_value: str
) -> None:
    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["rationale"] = unsafe_value
    with pytest.raises(EvidenceError):
        Corpus.model_validate(raw)


@pytest.mark.parametrize("slot", sorted(NESTED_SLOTS))
@pytest.mark.parametrize(
    "unsafe_value",
    [
        r"capture=C:\Customers\Acme\case.json",
        r"src=\\fileserver\share\case.json",
        "path:/var/lib/interlock/customer.db",
        "seefile/etc/passwd",
        "u=file:///etc/shadow",
        "mysk-proj-AbCdEf123456",
        "eyJhbGci.eyJzdWIi.dozjgNry",
        "eyJh.eyJz.dozj",
    ],
)
def test_nested_fields_reject_unsafe_values(
    corpus: Corpus, slot: str, unsafe_value: str
) -> None:
    raw = corpus.model_dump(mode="json", by_alias=True)
    NESTED_SLOTS[slot](raw["cases"][0], unsafe_value)
    with pytest.raises(EvidenceError):
        Corpus.model_validate(raw)


@pytest.mark.parametrize("path_class,payload", LOCAL_PATH_CLASS_VALUES.items())
@pytest.mark.parametrize("depth", range(MAX_URL_DECODE_DEPTH + 1))
def test_all_local_path_forms_fail_closed_in_text_nested_values_and_url_payloads(
    corpus: Corpus, path_class: str, payload: str, depth: int
) -> None:
    """Every local path class fails in all carrier forms at each decode depth."""
    encoded = _encoded_path_payload(payload, depth)

    # Free text covers a bare value and an ordinary key=value prefix. The
    # encoded value is still rejected in free text once decoding is relevant
    # only to URL carriers; the plain path form must always be caught here.
    for free_text in (payload, f"capture={payload}"):
        with pytest.raises(EvidenceError, match="unsafe filesystem path"):
            _assert_safe_value({"note": free_text}, f"{path_class}.text")

    # This is a real typed corpus path through a nested list, not just a
    # route-only scanner call.
    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["baseline"]["metadata"]["warnings"].append(f"capture={payload}")
    with pytest.raises(EvidenceError, match="unsafe filesystem path"):
        Corpus.model_validate(raw)

    for url in (
        f"https://example.com/?capture={encoded}",
        f"https://example.com/#capture={encoded}",
    ):
        with pytest.raises(EvidenceError, match="unsafe filesystem path"):
            assert_web_url_payload_safe(url, f"{path_class}.url")
        with pytest.raises(EvidenceError, match="unsafe filesystem path"):
            _assert_safe_value({"note": f"see {url}"}, f"{path_class}.url")
        raw = corpus.model_dump(mode="json", by_alias=True)
        raw["cases"][0]["source_url"] = url
        with pytest.raises((ValidationError, EvidenceError)):
            Corpus.model_validate(raw)


def test_rejected_local_path_forms_never_reach_generated_json_or_markdown(
    corpus: Corpus,
) -> None:
    """Validation stops every new local-path class before report rendering."""
    for payload in LOCAL_PATH_CLASS_VALUES.values():
        raw = corpus.model_dump(mode="json", by_alias=True)
        raw["cases"][0]["rationale"] = f"capture={payload}"
        with pytest.raises(EvidenceError, match="unsafe filesystem path"):
            report = build_report(
                Corpus.model_validate(raw),
                generated_at_utc="2026-01-01T00:00:00Z",
                revision="synthetic-revision",
                version="test-version",
            )
            rendered = render_json(report) + render_markdown(report)
            raise AssertionError(
                f"{payload!r} reached rendered output: {payload in rendered}"
            )


@pytest.mark.parametrize(
    "unsafe_value",
    [
        r"capture=C:\Customers\Acme\case.json",
        "path:/var/lib/interlock/customer.db",
        "eyJh.eyJz.dozj",
    ],
)
def test_schema_required_list_rejects_unsafe_values(
    corpus: Corpus, unsafe_value: str
) -> None:
    """`inputSchema.required` is guarded twice.

    The schema's own required-fields-exist check fires before the sanitizer, so
    either guard may report first. Both are hard validation failures raised
    before any case is evaluated.
    """
    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["baseline"]["tool"]["inputSchema"]["required"][0] = unsafe_value
    with pytest.raises((ValidationError, EvidenceError)):
        Corpus.model_validate(raw)


def test_unsafe_values_never_reach_generated_json_or_markdown(corpus: Corpus) -> None:
    """No reviewed unsafe value can survive as far as a rendered artifact."""
    blind_spot_index = next(
        index for index, case in enumerate(corpus.cases) if case.known_blind_spot
    )
    for unsafe_value in REVIEWED_UNSAFE_VALUES:
        for index in (0, blind_spot_index):
            raw = corpus.model_dump(mode="json", by_alias=True)
            raw["cases"][index]["rationale"] = unsafe_value
            with pytest.raises(EvidenceError):
                report = build_report(
                    Corpus.model_validate(raw),
                    generated_at_utc="2026-01-01T00:00:00Z",
                    revision="synthetic-revision",
                    version="test-version",
                )
                # Unreachable unless validation regressed; if it ever is
                # reached, prove the leak explicitly rather than passing.
                rendered = render_json(report) + render_markdown(report)
                raise AssertionError(
                    f"{unsafe_value!r} reached rendered output: "
                    f"{unsafe_value in rendered}"
                )


def test_blind_spot_references_are_stable_test_identifiers(corpus: Corpus) -> None:
    """Every unresolved blind spot must carry a reformat-proof reference."""
    blind_spots = [case for case in corpus.cases if case.known_blind_spot]
    assert len(blind_spots) == 7
    for case in blind_spots:
        assert TEST_IDENTIFIER_PATTERN.fullmatch(case.source_ref), case.case_id
        assert case.source_url.startswith("https://github.com/"), case.case_id
        assert "#L" not in case.source_url, case.case_id


def test_no_corpus_reference_pins_a_line_anchor(corpus: Corpus) -> None:
    """Line anchors are banned repo-wide in the corpus, not just for gaps."""
    raw = CORPUS_PATH.read_text(encoding="utf-8")
    assert "#L" not in raw
    for case in corpus.cases:
        assert not LINE_ANCHOR_PATTERN.search(case.source_url), case.case_id


@pytest.mark.parametrize(
    "anchored_url",
    [
        "https://github.com/org/repo/blob/main/tests/test_x.py#L120",
        "https://github.com/org/repo/blob/main/tests/test_x.py#L1-L20",
    ],
)
def test_corpus_rejects_reintroduced_line_anchors(
    corpus: Corpus, anchored_url: str
) -> None:
    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["source_url"] = anchored_url
    with pytest.raises(ValidationError, match="line anchor"):
        Corpus.model_validate(raw)


@pytest.mark.parametrize(
    "bad_ref",
    [
        "tests/test_drift_adversarial.py",
        "tests/test_drift_adversarial.py::",
        "test_fn1_blindspot_undeclared_capability_is_invisible",
        "tests/test_drift_adversarial.py#L136",
    ],
)
def test_blind_spot_rejects_unstable_source_ref(corpus: Corpus, bad_ref: str) -> None:
    raw = corpus.model_dump(mode="json", by_alias=True)
    blind = next(case for case in raw["cases"] if case["known_blind_spot"])
    blind["source_ref"] = bad_ref
    with pytest.raises((ValidationError, EvidenceError)):
        Corpus.model_validate(raw)


def test_referenced_test_functions_actually_exist(corpus: Corpus) -> None:
    """The stable identifiers must resolve to real test functions.

    This is the property a `#L` anchor could never provide: a line number
    always "resolves", even after it silently slides onto another statement.
    """
    referenced: dict[str, set[str]] = {}
    for case in corpus.cases:
        if "::" not in case.source_ref:
            continue
        file_part, test_name = case.source_ref.split("::", 1)
        referenced.setdefault(file_part, set()).add(test_name)

    assert referenced, "corpus should reference test functions"
    for file_part, names in referenced.items():
        target = ROOT / file_part
        assert target.is_file(), f"referenced test file missing: {file_part}"
        tree = ast.parse(target.read_text(encoding="utf-8"))
        defined = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        missing = sorted(names - defined)
        assert not missing, f"{file_part} is missing referenced tests: {missing}"


def test_shipped_github_source_urls_remain_valid(corpus: Corpus) -> None:
    """The path scanner must not reject legitimate complete source URLs."""
    urls = [case.source_url for case in corpus.cases if case.source_url]
    assert urls, "corpus should ship linked source URLs"
    assert all(url.startswith("https://github.com/") for url in urls)
    for url in urls:
        assert is_complete_web_url(url)
        _assert_safe_value({"source_url": url}, "case")
    # The rendered report carries them through untouched.
    report = build_report(
        corpus,
        generated_at_utc="2026-01-01T00:00:00Z",
        revision="synthetic-revision",
        version="test-version",
    )
    markdown = render_markdown(report)
    assert all(url in markdown for url in urls)


@pytest.mark.parametrize(
    "safe_url",
    [
        # A URL *path* component is public web routing, not a local path.
        "https://github.com/MaazAhmed47/Interlock/blob/main/tests/test_drift_adversarial.py#L120",
        "https://github.com/MaazAhmed47/Interlock/blob/main/tests/test_effective_permission_probes.py",
        "https://github.com/org/repo/blob/main/tests/test_x.py",
        "https://github.com/org/repo/blob/main/tests/test_x.py#L1-L20",
        "https://github.com/org/repo/tree/main/tests?tab=readme-ov-file",
        "http://example.com/a/b/c",
        "https://example.com/etc/passwd",
        "https://example.com/var/lib/data.db",
    ],
)
def test_complete_web_urls_are_not_treated_as_filesystem_paths(safe_url: str) -> None:
    assert is_complete_web_url(safe_url)
    assert_web_url_payload_safe(safe_url)
    _assert_safe_value({"source_url": safe_url}, "case")


@pytest.mark.parametrize("value", ["abc:example", "prefix abc:example end"])
def test_ordinary_colon_prose_is_not_mistaken_for_a_windows_drive_path(
    value: str,
) -> None:
    _assert_safe_value({"note": value}, "case")


# A complete URL is not a free pass: query and fragment values are ordinary
# carriers for arbitrary data, so they get the full credential/path scan after
# bounded recursive percent-decoding.
UNSAFE_URL_PAYLOADS = [
    # Plain query values.
    "https://example.com/?capture=/etc/passwd",
    "https://example.com/?capture=C:%5CCustomers%5CAcme%5Ccase.json",
    "https://example.com/?capture=%2Fvar%2Flib%2Fcustomer.db",
    r"https://example.com/?capture=C:\Customers\Acme\case.json",
    "https://example.com/?src=%5C%5Cfileserver%5Cshare%5Ccase.json",
    "https://example.com/path?query=/var/lib&x=1",
    # Double- and triple-encoded variants.
    "https://example.com/?capture=%252Fvar%252Flib%252Fcustomer.db",
    "https://example.com/?capture=%25252Fvar%25252Flib%25252Fcustomer.db",
    "https://example.com/?capture=C%253A%255CCustomers%255Ccase.json",
    # file:// smuggled through a query value.
    "https://example.com/?next=file%3A%2F%2F%2Fetc%2Fshadow",
    # Credentials and secrets in query values.
    "https://example.com/?token=Bearer%20abc123def456",
    "https://example.com/?api_key=abcd1234",
    "https://example.com/?k=sk-proj-AbCdEf123456",
    # Fragments carrying paths or credentials.
    "https://example.com/ok#/etc/passwd",
    "https://example.com/ok#capture=%2Fvar%2Flib%2Fcustomer.db",
    "https://example.com/ok#access_token=eyJh.eyJz.dozj",
    r"https://example.com/ok#C:\Customers\Acme\case.json",
]


@pytest.mark.parametrize("unsafe_url", UNSAFE_URL_PAYLOADS)
def test_url_query_and_fragment_payloads_are_rejected(unsafe_url: str) -> None:
    with pytest.raises(EvidenceError):
        assert_web_url_payload_safe(unsafe_url)
    with pytest.raises(EvidenceError):
        _assert_safe_value({"rationale": f"see {unsafe_url} for context"}, "case")


@pytest.mark.parametrize("unsafe_url", UNSAFE_URL_PAYLOADS)
def test_source_url_rejects_unsafe_query_and_fragment_payloads(
    corpus: Corpus, unsafe_url: str
) -> None:
    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["source_url"] = unsafe_url
    with pytest.raises((ValidationError, EvidenceError)):
        Corpus.model_validate(raw)


@pytest.mark.parametrize(
    "credential_url",
    [
        "https://user:pass@github.com/org/repo",
        "https://user@github.com/org/repo",
        "http://admin:hunter2@internal.example.com/x",
    ],
)
def test_url_userinfo_credentials_are_rejected_everywhere(
    corpus: Corpus, credential_url: str
) -> None:
    """A credential URL must fail in free text, not merely go un-stripped."""
    assert not is_complete_web_url(credential_url)
    with pytest.raises(EvidenceError, match="forbidden sensitive value"):
        _assert_safe_value({"rationale": f"see {credential_url} here"}, "case")
    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["rationale"] = f"documented at {credential_url}"
    with pytest.raises(EvidenceError):
        Corpus.model_validate(raw)


@pytest.mark.parametrize(
    "safe_authority_url",
    [
        "https://example.com:8443/a/b",
        "https://github.com/org/repo",
    ],
)
def test_host_port_authority_is_not_mistaken_for_credentials(
    safe_authority_url: str,
) -> None:
    assert is_complete_web_url(safe_authority_url)
    _assert_safe_value({"source_url": safe_authority_url}, "case")


def test_url_decoding_depth_is_bounded() -> None:
    """Decoding is repeated, but only to the documented bound."""
    assert MAX_URL_DECODE_DEPTH == 3
    # Encoded one layer beyond the bound: still not a silent pass, because the
    # residual encoded text is what gets scanned rather than a decoded path.
    over_bound = "%25" * MAX_URL_DECODE_DEPTH + "2Fvar%2Flib"
    variants = _decoded_variants(over_bound)
    assert len(variants) <= MAX_URL_DECODE_DEPTH + 1
    # Within the bound, the hidden path is recovered and caught.
    assert any(
        "/var/lib" in variant for variant in _decoded_variants("%252Fvar%252Flib")
    )


@pytest.mark.parametrize(
    "value",
    [
        # Containing a URL must not exempt the rest of the string.
        "https://github.com/MaazAhmed47/Interlock see capture=/etc/passwd",
        r"https://example.com/ok and src:C:\Customers\Acme\case.json",
        "https://example.com/ok and file:///etc/shadow",
        # Incomplete URL fragments are not stripped and stay fail-closed.
        "https:// /etc/passwd",
    ],
)
def test_url_presence_does_not_exempt_surrounding_text(value: str) -> None:
    with pytest.raises(EvidenceError, match="unsafe filesystem path"):
        _assert_safe_value({"rationale": value}, "case")


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/shadow",
        "not-a-url",
        "/etc/passwd",
        "https://",
        "https://user:pass@github.com/x",
        "https://github.com/a b",
    ],
)
def test_source_url_must_be_a_complete_web_url(corpus: Corpus, bad_url: str) -> None:
    raw = corpus.model_dump(mode="json", by_alias=True)
    raw["cases"][0]["source_url"] = bad_url
    with pytest.raises((ValidationError, EvidenceError)):
        Corpus.model_validate(raw)


@pytest.mark.parametrize(
    "benign_value",
    [
        "tests/test_drift_adversarial.py::test_fn1_blindspot",
        "tests/integration/nested/test_case.py",
        "A risk-based review of task-runner behaviour.",
        "Adding a disk-usage field changes no capability.",
        "Ratio 1:2 measured at 12:30 across read/write modes.",
        "files.read scope unchanged",
    ],
)
def test_benign_text_is_not_falsely_rejected(benign_value: str) -> None:
    _assert_safe_value({"rationale": benign_value}, "case")


def test_expected_decision_change_fails_closed(corpus: Corpus) -> None:
    changed = corpus.model_copy(deep=True)
    changed.cases[0].expected_interlock_decision = "allow"
    with pytest.raises(EvidenceError, match="DQV1-SURFACE-001"):
        build_report(changed)


def test_cli_writes_both_formats_and_invalid_corpus_fails_nonzero(
    tmp_path: Path, corpus: Corpus
) -> None:
    output_dir = tmp_path / "report"
    completed = subprocess.run(
        [sys.executable, str(CLI), "--output-dir", str(output_dir)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert (output_dir / "detection-quality-evidence.v1.json").is_file()
    assert (output_dir / "detection-quality-evidence.v1.md").is_file()

    invalid = corpus.model_dump(mode="json")
    del invalid["cases"][0]["expected_ground_truth_label"]
    invalid_path = tmp_path / "invalid-corpus.json"
    invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(CLI), "--corpus", str(invalid_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert failed.returncode != 0
    assert "expected_ground_truth_label" in failed.stderr

    zero_denominator = corpus.model_dump(mode="json")
    zero_denominator["cases"] = [
        case
        for case in zero_denominator["cases"]
        if case["case_id"] == "DQV1-PROBE-002"
    ]
    zero_path = tmp_path / "zero-denominator-corpus.json"
    zero_path.write_text(json.dumps(zero_denominator), encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(CLI), "--corpus", str(zero_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert failed.returncode != 0
    assert "invalid zero metric denominator" in failed.stderr

    changed_decision = corpus.model_dump(mode="json")
    changed_decision["cases"][0]["expected_interlock_decision"] = "allow"
    changed_path = tmp_path / "changed-decision-corpus.json"
    changed_path.write_text(json.dumps(changed_decision), encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(CLI), "--corpus", str(changed_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert failed.returncode != 0
    assert "expected Interlock decision changed" in failed.stderr

    forbidden = corpus.model_dump(mode="json")
    forbidden["cases"][0]["baseline"]["authorization"] = "synthetic"
    forbidden_path = tmp_path / "forbidden-field-corpus.json"
    forbidden_path.write_text(json.dumps(forbidden), encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(CLI), "--corpus", str(forbidden_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert failed.returncode != 0
    assert "extra_forbidden" in failed.stderr
