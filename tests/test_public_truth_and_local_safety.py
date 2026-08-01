import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OFFLINE_COMPOSE = ROOT / "demo" / "offline" / "docker-compose.yml"

# ── repository-wide quarantine-scope contract ────────────────────────────────
#
# Quarantine is keyed by (server_id, tool_name): core/db.py updates
# `mcp_tool_metadata ... WHERE server_id = ? AND tool_name = ?`, and
# core/mcp_gateway.py returns `tool_quarantined` only for that stored tool. The
# offline evaluator asserts `blocked_tools == 1` while its control tool keeps
# working. So a public claim that "subsequent gateway-mediated calls are held"
# WITHOUT naming the affected tool reads as a server-wide pause, which is false.
#
# Detection is clause-level. Paragraph-level co-occurrence produced false
# positives (numbered question lists, code constants such as "held-call.json"),
# and sentence-splitting severed real claims from their quarantine context.

_W = r"(?:[\w`*/,-]+ ){0,6}"
_FOLLOWING = r"(?:next|later|subsequent|following|followed by)"
_STOPPED = (
    r"(?:held|hold|blocked|denied|stopped|not forwarded"
    r"|before (?:any )?(?:upstream|provider|forwarding)"
    r"|before (?:the )?(?:gateway |interlock )?forwards?"
    # "returns tool_quarantined" is itself the stop outcome.
    r"|returns? `?tool_quarantined"
    # "...before Interlock sends an upstream `tools/call`" — a hold stated as a
    # non-send rather than a non-forward. Missed by the forward-only patterns.
    r"|before (?:\w+ |`[^`]*` ){0,3}(?:sends?|forwards?|issues?|dispatches?|emits?)\b)"
)

_CLAIM_PATTERNS = (
    re.compile(
        rf"{_FOLLOWING}\s+{_W}calls?\b\s*{_W}(?:are |is |can |then |be |get )*{_STOPPED}",
        re.I,
    ),
    re.compile(
        rf"\b(?:hold|holds|holding|deny|denies|denying|block|blocks)[\w/]*\s+{_W}"
        rf"{_FOLLOWING}\s+{_W}calls?\b",
        re.I,
    ),
    re.compile(rf"quarantine on\s+{_W}{_FOLLOWING}\s+{_W}calls?\b", re.I),
)

_TOOL_QUALIFIER = re.compile(
    r"\bto (?:that|the|this|its|such|each|affected|quarantined|drifted|changed)"
    r"(?: same| one)? tool\b"
    r"|\bto [a-z_]*read_file\b"
    # Naming any specific tool scopes the claim, including a code-formatted
    # identifier such as "calls to `read_file`" or "to `update_record`".
    r"|\bto [`'\"]+[a-z_][a-z0-9_]*[`'\"]*"
    r"|\bto a (?:quarantined|drifted)\b"
    r"|\bthat tool\b|\baffected tool\b|\bquarantined tool\b|\bdrifted tool\b"
    r"|\bper tool\b|\btool-scoped\b|\bthat one tool\b|\bto it\b",
    re.I,
)

# Planned-chain rejection and argument-policy denial are different controls and
# make no claim about tool-quarantine breadth.
_OTHER_CONTROL = re.compile(
    r"chain|planned sequence|orchestrator|argument bound|argument polic", re.I
)
# A receipt reason or decision object already identifies one exact call through
# structured fields, so it needs no prose tool qualifier.
_STRUCTURED = re.compile(r'"tool_name"|"tool_ref"|"target"\s*:')

_TABLE = re.compile(r"^\s*\|")
_NEW_ITEM = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s|#{1,6}\s|```)")
_SENTENCE_END = re.compile(r"[.!?:;]\s*$|[.!?]\s*\*{0,2}\s*$")


def _claim_blocks(path: Path):
    """Yield (line_no, text) sentence-continuation blocks.

    Lines are joined only while the sentence is still open, so a wrapped claim
    stays intact without an unrelated neighbouring line rescuing a bad one.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix in {".html", ".tsx"}:
        text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.S | re.I)
        text = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.S | re.I)
        text = re.sub(r"<br\s*/?>", " . ", text)
        text = re.sub(r"<[^>]+>", " ", text)
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start, buf = i, [lines[i]]
        if not (_TABLE.match(lines[i]) or path.suffix in {".html", ".tsx"}):
            while (
                not _SENTENCE_END.search(buf[-1])
                and i + 1 < len(lines)
                and lines[i + 1].strip()
                and not _TABLE.match(lines[i + 1])
                and not _NEW_ITEM.match(lines[i + 1])
            ):
                i += 1
                buf.append(lines[i])
        i += 1
        unit = re.sub(r"\s+", " ", " ".join(buf)).strip()
        if unit:
            yield start + 1, unit


def public_claim_surfaces(root=ROOT):
    surfaces = [
        root / n for n in ("README.md", "RELEASE_NOTES.md", "ROADMAP.md", "SECURITY.md")
    ]
    surfaces += sorted((root / "docs").rglob("*.md"))
    surfaces += sorted((root / "demo").rglob("*.md"))
    surfaces += sorted((root / "demo").rglob("*.py"))
    surfaces += [root / "interlock-web" / "index.html"]
    surfaces += sorted((root / "interlock-web" / "src").rglob("*.tsx"))
    return [p for p in surfaces if p.exists()]


def unscoped_quarantine_claims(root=ROOT):
    """Return [(path, line, excerpt)] for holding claims missing a tool scope."""
    found = []
    for path in public_claim_surfaces(root):
        for lineno, unit in _claim_blocks(path):
            if _STRUCTURED.search(unit) or _OTHER_CONTROL.search(unit):
                continue
            for pattern in _CLAIM_PATTERNS:
                match = pattern.search(unit)
                if not match:
                    continue
                # The qualifier must sit NEXT TO the claim; searching the whole
                # sentence let an unrelated earlier clause rescue a bad claim.
                near = unit[max(0, match.start() - 40) : match.end() + 90]
                if _TOOL_QUALIFIER.search(near):
                    continue
                found.append(
                    (path.relative_to(root).as_posix(), lineno, match.group(0).strip())
                )
                break
    return found


def test_root_moving_mcp_integration_is_absent():
    assert not (ROOT / ".mcp.json").exists()


def test_root_compose_gateway_publishes_on_loopback_only():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["services"]["interlock"]["ports"] == ["127.0.0.1:8001:8001"]


def test_offline_compose_uses_project_scoped_container_names():
    compose = yaml.safe_load(OFFLINE_COMPOSE.read_text(encoding="utf-8"))
    assert all(
        "container_name" not in service for service in compose["services"].values()
    )


def test_default_evaluator_and_advanced_behavioral_probe_are_distinct():
    readme = (ROOT / "demo" / "offline" / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "evaluator-quickstart.md").read_text(encoding="utf-8")

    assert "Capability / surface drift (default evaluator proof)" in readme
    assert "Behavioral / effective-permission drift (separate advanced proof)" in readme
    assert "does not run the 403-to-200 behavioral probe" in guide
    assert "The controlled probe is forwarded" in readme
    assert (
        "A later gateway-mediated call **to that\n   same tool** is not forwarded"
        in readme
    )
    # The default proof must name the tool it actually runs and say quarantine
    # is per tool, not a server-wide pause.
    assert "`read_file`" in readme
    assert "quarantine is per tool, not a\n   server-wide pause" in readme
    assert "`list_documents` control tool keeps working" in readme


def _demo_scenario(name):
    """Return the source of one scenario method from the offline demo runner."""
    source = (ROOT / "demo" / "offline" / "run_demo.py").read_text(encoding="utf-8")
    start = source.index(f"def {name}(")
    nxt = source.find("\n    def ", start)
    return source[start : nxt if nxt != -1 else len(source)]


def test_default_demo_scenario_never_claims_the_403_to_200_probe():
    """scenario-a is surface drift only; a 403->200 claim there is a lie."""
    scenario_a = _demo_scenario("scenario_a")

    assert "403" not in scenario_a
    assert "re-discovery" in scenario_a
    assert "held before upstream forwarding" in scenario_a
    # It must not say the tool is stopped before *any* call could ever run.
    assert "BEFORE any" not in scenario_a
    # Quarantine is per (server_id, tool_name): core/db.py updates
    # mcp_tool_metadata WHERE server_id = ? AND tool_name = ?. Saying "the next
    # gateway-mediated call is held" without naming the tool reads as a
    # server-wide pause, which is false.
    assert "quarantines that one tool" in scenario_a
    assert "mediated call to it is held before upstream forwarding" in scenario_a
    assert "Other" in scenario_a and "approved tools keep working" in scenario_a
    assert "later call to that tool held" in scenario_a


def test_advanced_demo_scenario_states_the_probe_is_forwarded():
    """scenario-b must own that the probe executes upstream to be observed."""
    scenario_b = _demo_scenario("scenario_b")

    assert "IS forwarded" in scenario_b
    assert "needs the upstream response to observe" in scenario_b
    assert "only later" in scenario_b
    # Tool-scoped, for the same reason as scenario-a.
    assert "gateway-mediated calls to that same tool are held before forwarding" in (
        scenario_b
    )


def test_demo_holding_claims_never_imply_a_server_wide_pause():
    """No demo surface may claim unrelated gateway traffic is held."""
    sources = [
        (ROOT / "demo" / "offline" / "run_demo.py").read_text(encoding="utf-8"),
        (ROOT / "demo" / "offline" / "mock_server" / "server.py").read_text(
            encoding="utf-8"
        ),
    ]
    overbroad = (
        "the next gateway-mediated call is held",
        "gateway-mediated calls are held before forwarding",
        "later gateway call held before forwarding",
        "subsequent gateway-mediated calls are held",
    )
    for source in sources:
        for phrase in overbroad:
            assert phrase not in source, f"unscoped holding claim: {phrase}"


def test_demo_runner_help_separates_the_default_path_from_the_probe():
    source = (ROOT / "demo" / "offline" / "run_demo.py").read_text(encoding="utf-8")
    docstring = source[
        source.index('"""') : source.index('"""', source.index('"""') + 3)
    ]

    assert "The default path (scenario-a) never runs this probe." in docstring
    assert "controlled non-production probe IS" in docstring


def test_public_claims_do_not_use_unscoped_before_execution_wording():
    claim_files = [ROOT / "README.md", ROOT / "ROADMAP.md", ROOT / "RELEASE_NOTES.md"]
    claim_files.extend((ROOT / "docs").rglob("*.md"))
    claim_files.extend((ROOT / "interlock-web").glob("*.html"))
    claim_files.extend((ROOT / "interlock-web" / "src").rglob("*.tsx"))
    claim_files.extend((ROOT / "demo").rglob("*.py"))

    offenders = []
    for path in claim_files:
        if "before execution" in path.read_text(encoding="utf-8").lower():
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_roadmap_matches_scoped_official_sdk_interoperability_evidence():
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    assert (
        "Tested, pinned official-SDK interoperability; not full MCP conformance"
        in roadmap
    )
    assert "not certified against the official MCP SDK" not in roadmap
    assert "Official MCP SDK adoption" not in roadmap


def test_security_distinguishes_implemented_oidc_from_unsupported_saml():
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "OIDC admin authentication is implemented" in security
    assert "SAML is not implemented" in security
    assert "until native OIDC/SAML is implemented" not in security


def test_no_public_quarantine_claim_reads_as_a_server_wide_pause():
    """Every 'later calls are held' claim must name the affected tool."""
    offenders = unscoped_quarantine_claims()
    detail = "\n".join(f"  {p}:{n}\n      {excerpt}" for p, n, excerpt in offenders)
    assert not offenders, (
        "quarantine is per (server_id, tool_name); these public claims omit the "
        f"affected tool and read as a server-wide gateway pause:\n{detail}"
    )


def test_claim_scanner_actually_detects_an_unscoped_claim(tmp_path):
    """Guard the guard: a vacuous scanner would make the contract worthless."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "demo").mkdir()
    (tmp_path / "interlock-web" / "src").mkdir(parents=True)
    (tmp_path / "README.md").write_text(
        "After drift, Interlock holds subsequent gateway-mediated calls "
        "before upstream forwarding.\n",
        encoding="utf-8",
    )
    assert unscoped_quarantine_claims(tmp_path), "scanner missed an unscoped claim"

    (tmp_path / "README.md").write_text(
        "After drift, Interlock holds subsequent gateway-mediated calls to that "
        "tool before upstream forwarding.\n",
        encoding="utf-8",
    )
    assert not unscoped_quarantine_claims(tmp_path), "scanner false-positives"


def test_scanner_does_not_flag_non_quarantine_controls(tmp_path):
    """Chain rejection and structured receipt reasons are different controls."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "demo").mkdir()
    (tmp_path / "interlock-web" / "src").mkdir(parents=True)
    (tmp_path / "README.md").write_text(
        "Critical chain findings are denied before the orchestrator forwards "
        "subsequent provider calls.\n"
        'A receipt records {"tool_name": "read_file"} when the next call is '
        "not forwarded.\n",
        encoding="utf-8",
    )
    assert unscoped_quarantine_claims(tmp_path) == []


# Every location the independent review named, plus the two it missed
# (ROADMAP.md effect-drift note, agentic-runtime-governance stop-mechanism row).
REPAIRED_CLAIM_SITES = {
    "README.md": (
        "hold subsequent gateway-mediated calls to it before forwarding",
        "holds the subsequent gateway-mediated call to that tool before",
        "enforce quarantine on the affected tool",
        "followed by a gateway-mediated call to that tool held before",
    ),
    "ROADMAP.md": ("Subsequent calls to that tool are blocked by the",),
    "demo/run_db_drift_ab.py": ("quarantines that one tool",),
    "docs/agentic-runtime-governance.md": (
        "hold subsequent gateway calls to it before upstream forwarding",
    ),
    "docs/interlock-enterprise-boundary-controls.md": (
        "deny subsequent gateway calls to it before provider forwarding",
    ),
    "docs/interlock-owasp-mcp-coverage.md": (
        "subsequent gateway-mediated calls to it can then be held",
    ),
    "docs/mcp-registry-audit.md": ("subsequent gateway calls to it can be held",),
    "docs/mcp-runtime-security-threat-model.md": (
        "Hold subsequent gateway-mediated calls to that tool",
    ),
    "docs/mcp-vulnerability-coverage-map.md": (
        "hold subsequent gateway calls to it before upstream forwarding",
        "quarantine that tool and hold subsequent gateway-mediated calls to it",
        "quarantine of that tool, and can hold subsequent gateway-mediated calls to it",
    ),
}


def test_every_known_residual_location_states_the_affected_tool():
    missing = []
    for rel, phrases in REPAIRED_CLAIM_SITES.items():
        source = (ROOT / rel).read_text(encoding="utf-8")
        for phrase in phrases:
            if phrase not in source:
                missing.append(f"{rel}: expected {phrase!r}")
    assert not missing, "repaired wording regressed:\n" + "\n".join(missing)


# The exact construction independent review found: the claim sentence leans on
# the PRECEDING sentence for its subject, so read alone it asserts that any
# subsequent gateway call is stopped. The scanner must not need that context.
_UNSCOPED_CONSTRUCTION = (
    "Interlock quarantines the stored tool. A subsequent call through "
    "`/mcp/call` returns `tool_quarantined` before Interlock sends an upstream "
    "`tools/call`."
)
_SCOPED_CONSTRUCTION = (
    "Interlock quarantines the stored `read_file` tool. A subsequent "
    "gateway-mediated call to `read_file` through `/mcp/call` returns "
    "`tool_quarantined`, and Interlock sends no upstream `tools/call` for "
    "`read_file`."
)


def _scan_text(tmp_path, body):
    """Run the real repo scanner over a single synthetic surface."""
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "demo").mkdir(exist_ok=True)
    (tmp_path / "interlock-web" / "src").mkdir(parents=True, exist_ok=True)
    (tmp_path / "README.md").write_text(body + "\n", encoding="utf-8")
    return unscoped_quarantine_claims(tmp_path)


def test_scanner_flags_a_hold_stated_as_a_non_send(tmp_path):
    """ "...before Interlock sends an upstream tools/call" is a holding claim.

    The forward-only patterns missed it, so an unscoped claim shipped in the
    evaluator guide. Equivalent wording must stay covered, not just this string.
    """
    assert _scan_text(tmp_path, _UNSCOPED_CONSTRUCTION), (
        "scanner must flag a quarantine hold phrased as 'before Interlock sends "
        "an upstream tools/call' without naming the affected tool"
    )
    assert (
        _scan_text(tmp_path, _SCOPED_CONSTRUCTION) == []
    ), "explicitly naming read_file must satisfy the contract"


def test_scanner_covers_equivalent_unscoped_phrasings(tmp_path):
    """Semantic coverage, not one pinned string."""
    for variant in (
        "After drift, a subsequent call returns `tool_quarantined` before "
        "Interlock sends an upstream `tools/call`.",
        "Once quarantined, the next gateway-mediated call is denied before "
        "Interlock issues an upstream request.",
        "Later gateway calls return `tool_quarantined` before the gateway "
        "forwards anything upstream.",
    ):
        assert _scan_text(tmp_path, variant), f"missed equivalent phrasing: {variant}"

    for scoped in (
        "After drift, a subsequent call to that tool returns `tool_quarantined` "
        "before Interlock sends an upstream `tools/call`.",
        "Once quarantined, the next gateway-mediated call to `read_file` is "
        "denied before Interlock issues an upstream request.",
    ):
        assert _scan_text(tmp_path, scoped) == [], f"false positive: {scoped}"


def test_evaluator_guide_names_the_quarantined_tool_without_borrowed_context():
    guide = (ROOT / "docs" / "evaluator-quickstart.md").read_text(encoding="utf-8")
    assert "quarantines the stored `read_file` tool" in guide
    assert (
        "subsequent gateway-mediated call to `read_file` through `/mcp/call`" in guide
    )
    assert "sends no upstream `tools/call` for `read_file`" in guide
    assert "Quarantine is scoped to that one tool, not to the server" in guide
    assert "`list_documents` control tool keeps working" in guide


def test_readme_headline_quarantines_a_tool_not_a_call():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    # The state transition is: tool -> quarantined; LATER calls to it -> held.
    assert "quarantines changed gateway-mediated calls" not in readme
    scoped = (
        "quarantines the affected tool so that later gateway-mediated calls to "
        "that tool are held before upstream forwarding"
    )
    assert readme.count(scoped) == 2, "both headline claims must state tool quarantine"
    # The first forwarded behavioral probe must never be described as held.
    assert "quarantine before a changed gateway-mediated call continues" not in readme
    assert "the next gateway-mediated call to `read_file` is held before any" in readme
    assert "passes hash-chain verification" in readme
