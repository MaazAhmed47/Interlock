import json
import os
import hashlib
import re
from datetime import datetime, timezone
from models.schemas import ScanResult, ThreatLevel

MEMORY_FILE = "data/learned_patterns.json"


def _ensure_file():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(MEMORY_FILE):
        with open(MEMORY_FILE, "w") as f:
            json.dump({"patterns": [], "false_negatives": []}, f)


def _load() -> dict:
    _ensure_file()
    with open(MEMORY_FILE, "r") as f:
        return json.load(f)


def _save(data: dict):
    _ensure_file()
    with open(MEMORY_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _fingerprint(prompt: str) -> str:
    # Normalize and hash the prompt for fuzzy matching
    normalized = re.sub(r"\s+", " ", prompt.lower().strip())
    normalized = re.sub(r"[^\w\s]", "", normalized)
    return hashlib.md5(normalized.encode()).hexdigest()


def _extract_keywords(prompt: str) -> list[str]:
    words = re.findall(r"\b\w{4,}\b", prompt.lower())
    stopwords = {
        "this",
        "that",
        "with",
        "have",
        "will",
        "from",
        "they",
        "been",
        "were",
        "what",
    }
    return [w for w in words if w not in stopwords][:10]


def learn_from_result(prompt: str, result: ScanResult):
    """Save LLM Judge decisions so we learn from them."""
    if result.layer_caught != "Layer 3 — LLM Judge":
        return  # Only learn from LLM decisions

    data = _load()
    keywords = _extract_keywords(prompt)
    fingerprint = _fingerprint(prompt)

    # Don't store duplicates
    existing = [p["fingerprint"] for p in data["patterns"]]
    if fingerprint in existing:
        return

    pattern = {
        "fingerprint": fingerprint,
        "keywords": keywords,
        "is_threat": result.is_threat,
        "threat_level": result.threat_level.value,
        "threat_type": result.threat_type,
        "reason": result.reason,
        "confidence": result.confidence,
        "learned_at": datetime.now(timezone.utc).isoformat(),
        "times_matched": 0,
    }

    data["patterns"].append(pattern)
    _save(data)


def report_false_negative(prompt: str, correct_threat_type: str):
    """Report a missed threat so the system learns."""
    data = _load()
    data["false_negatives"].append(
        {
            "prompt": prompt[:200],
            "keywords": _extract_keywords(prompt),
            "correct_threat_type": correct_threat_type,
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    _save(data)


def check_learned_patterns(prompt: str) -> ScanResult | None:
    """Check if we've seen a similar prompt before."""
    try:
        data = _load()
        if not data["patterns"]:
            return None

        prompt_keywords = set(_extract_keywords(prompt))
        best_match = None
        best_score: float = 0.0

        for pattern in data["patterns"]:
            if not pattern["is_threat"]:
                continue  # Only match learned threats

            learned_keywords = set(pattern["keywords"])
            if not learned_keywords:
                continue

            # Calculate keyword overlap
            overlap = len(prompt_keywords & learned_keywords)
            score = overlap / len(learned_keywords)

            # 70% keyword overlap = similar prompt
            if score >= 0.7 and score > best_score:
                best_score = score
                best_match = pattern

        if best_match:
            best_match["times_matched"] += 1
            _save(data)

            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel(best_match["threat_level"]),
                threat_type=best_match["threat_type"],
                reason=f"[Learned Pattern] Similar to previously confirmed threat. "
                f"Match score: {round(best_score * 100)}%. Original: {best_match['reason'][:100]}",
                original_prompt=prompt,
                safe_to_proceed=False,
                confidence=round(best_match["confidence"] * best_score, 2),
                layer_caught="Layer 0 — Learned Memory",
            )

        return None

    except Exception:
        return None
