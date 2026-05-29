import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mcp_drift import classify_tool_drift, classify_server_drift


# ── Description edit distance ──────────────────────────────────────────────────

def test_small_description_change_is_minor():
    prev = {"description": "Read a file from disk.", "inputSchema": {}}
    curr = {"description": "Read a file from disk safely.", "inputSchema": {}}
    result = classify_tool_drift(prev, curr, {}, {})
    desc_finding = next((f for f in result["findings"] if f["type"] == "description_changed"), None)
    assert desc_finding is not None
    assert desc_finding["severity"] == "minor"


def test_large_description_change_elevates_to_moderate():
    prev = {"description": "Read a file from disk and return its contents.", "inputSchema": {}}
    curr = {"description": "Execute arbitrary shell commands with elevated privileges.", "inputSchema": {}}
    result = classify_tool_drift(prev, curr, {}, {})
    desc_finding = next((f for f in result["findings"] if f["type"] == "description_changed"), None)
    assert desc_finding is not None
    assert desc_finding["severity"] == "moderate"


# ── Parameter type changes ─────────────────────────────────────────────────────

def test_param_type_change_detected():
    prev = {
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "string"}},
        }
    }
    curr = {
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer"}},
        }
    }
    result = classify_tool_drift(prev, curr, {}, {})
    type_finding = next((f for f in result["findings"] if f["type"] == "param_type_changed"), None)
    assert type_finding is not None
    assert type_finding["severity"] == "moderate"
    assert "limit" in type_finding["reason"]


def test_no_type_change_no_finding():
    schema = {
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
        }
    }
    result = classify_tool_drift(schema, schema, {}, {})
    assert not any(f["type"] == "param_type_changed" for f in result["findings"])


# ── Server-level drift: tool removal / addition ────────────────────────────────

def test_tool_removal_is_critical():
    findings = classify_server_drift(
        server_id="my-server",
        prev_tool_names={"read_file", "write_file"},
        curr_tool_names={"read_file"},
    )
    removed = [f for f in findings if f["type"] == "tool_removed"]
    assert len(removed) == 1
    assert removed[0]["severity"] == "critical"
    assert removed[0]["tool_name"] == "write_file"


def test_tool_addition_is_high():
    findings = classify_server_drift(
        server_id="my-server",
        prev_tool_names={"read_file"},
        curr_tool_names={"read_file", "exec_shell"},
    )
    added = [f for f in findings if f["type"] == "tool_added"]
    assert len(added) == 1
    assert added[0]["severity"] == "high"
    assert added[0]["tool_name"] == "exec_shell"


def test_no_server_drift_when_tools_unchanged():
    findings = classify_server_drift(
        server_id="s",
        prev_tool_names={"a", "b"},
        curr_tool_names={"a", "b"},
    )
    assert findings == []


def test_multiple_removals_and_additions():
    findings = classify_server_drift(
        server_id="s",
        prev_tool_names={"a", "b", "c"},
        curr_tool_names={"a", "d", "e"},
    )
    removed = [f for f in findings if f["type"] == "tool_removed"]
    added = [f for f in findings if f["type"] == "tool_added"]
    assert {f["tool_name"] for f in removed} == {"b", "c"}
    assert {f["tool_name"] for f in added} == {"d", "e"}
