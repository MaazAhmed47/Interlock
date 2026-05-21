"""
Regression test: Interlock must import and run basic scans without GROQ_API_KEY.

Run: python tests/test_llm_judge_no_key.py
"""
import importlib
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.pop("GROQ_API_KEY", None)
os.environ.pop("DATABASE_URL", None)
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ["FIREWALL_DB_PATH"] = tempfile.mktemp(suffix="_no_key_test.db")

import core.db as db
db.DB_PATH = os.environ["FIREWALL_DB_PATH"]
db.init_db()
db.seed_legacy_keys()

judge = importlib.import_module("core.llm_judge")
assert judge.client is None, "Groq client should be disabled when GROQ_API_KEY is absent"

result = judge.llm_judge_scan(
    "plain local startup test",
    api_key="lf-dev-key-456",
    prior_layers_safe=True,
)

assert result.safe_to_proceed is True, result
assert result.is_threat is False, result
assert "GROQ_API_KEY not configured" in result.reason, result.reason

print("No-key LLM judge startup test passed.")
