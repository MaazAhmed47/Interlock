from models.schemas import ScanResult, ThreatLevel
import re

THREAT_SIGNALS = {
    # ── Direct injection ──────────────────────────────────────────
    "ignore instructions": 9,
    "ignore previous": 9,
    "ignore all": 8,
    "forget instructions": 9,
    "forget everything": 8,
    "override instructions": 9,
    "bypass restrictions": 9,
    "bypass safety": 10,
    "disregard instructions": 9,
    "disregard previous": 8,
    "disregard all": 8,
    # ── Persona/roleplay attacks ──────────────────────────────────
    "new persona": 7,
    "act as if": 6,
    "pretend you are": 7,
    "pretend to be": 7,
    "you are now": 6,
    "roleplay as": 5,
    "simulate being": 6,
    "character who": 5,
    "play the role": 6,
    "stay in character": 5,
    "never break character": 7,
    "from now on you": 8,
    "your new identity": 8,
    "your true self": 6,
    "your real personality": 7,
    # ── Jailbreak classics ────────────────────────────────────────
    "no restrictions": 8,
    "no rules": 7,
    "no limits": 6,
    "without limits": 6,
    "evil ai": 9,
    "unrestricted ai": 9,
    "jailbreak": 10,
    "dan mode": 10,
    "developer mode": 8,
    "god mode": 7,
    "do anything now": 10,
    "do anything you want": 8,
    "dude mode": 8,
    "stan mode": 7,
    "anti-gpt": 8,
    "anti-claude": 8,
    "opposite mode": 7,
    "evil mode": 9,
    "chaos mode": 7,
    "dark mode personality": 8,
    "unfiltered": 8,
    "uncensored": 8,
    "without censorship": 8,
    # ── System prompt extraction ──────────────────────────────────
    "reveal system prompt": 10,
    "show system prompt": 10,
    "print your instructions": 9,
    "what are your instructions": 6,
    "tell me your prompt": 8,
    "display your prompt": 8,
    "output your instructions": 9,
    "repeat your system": 9,
    "what is your system": 6,
    "initial prompt": 7,
    "starting prompt": 6,
    "original instructions": 7,
    "hidden instructions": 8,
    "secret instructions": 8,
    "confidential instructions": 8,
    "system message": 8,
    "reveal the system": 9,
    "reveal system message": 10,
    "secret environment": 9,
    "environment variables": 8,
    "forget prior rules": 9,
    "forget all prior rules": 10,
    "root instruction": 8,
    # ── Social engineering ────────────────────────────────────────
    "my boss told you": 6,
    "you have been updated": 7,
    "new instructions from": 8,
    "your creator says": 7,
    "anthropic says": 6,
    "openai says": 6,
    "your developers say": 7,
    "maintenance mode": 6,
    "debug mode": 6,
    "test mode": 5,
    "admin mode": 8,
    "sudo mode": 8,
    "superuser": 7,
    "root access": 8,
    "override code": 8,
    "master password": 9,
    "access granted": 6,
    "you are authorized": 6,
    "i am your developer": 9,
    "i work at anthropic": 9,
    "i work at openai": 9,
    "internal testing": 6,
    # ── Context manipulation ──────────────────────────────────────
    "hypothetically speaking": 5,
    "for a story": 4,
    "for my novel": 4,
    "for a movie": 4,
    "for educational purposes": 4,
    "academically speaking": 4,
    "theoretically": 3,
    "just curious": 3,
    "asking for a friend": 4,
    "thought experiment": 4,
    "what if scenario": 4,
    "in a parallel universe": 5,
    "in fiction": 3,
    "fictional character": 4,
    "in a game": 3,
    # ── Harmful content ───────────────────────────────────────────
    "how to make a bomb": 10,
    "how to build a bomb": 10,
    "how to hack": 7,
    "how to exploit": 7,
    "step by step hack": 9,
    "ddos attack": 8,
    "sql injection": 6,
    "xss attack": 7,
    "ransomware": 8,
    "malware": 7,
    "trojan horse": 6,
    "keylogger": 7,
    "phishing": 6,
    "social engineering attack": 7,
    "how to stalk": 9,
    "how to poison": 9,
    "how to hurt": 8,
    "how to kill": 10,
    "how to synthesize": 7,
    "drug synthesis": 9,
    "weapon instructions": 10,
    "how to make drugs": 10,
    # ── Prompt leaking tricks ─────────────────────────────────────
    "translate the above": 7,
    "summarize the above": 6,
    "repeat after me": 6,
    "say exactly": 6,
    "output exactly": 7,
    "print exactly": 7,
    "echo the": 6,
    "copy the above": 7,
    "what did i just": 5,
    "what was the first": 5,
    # ── Encoding/obfuscation tricks ───────────────────────────────
    "base64 decode": 7,
    "rot13": 6,
    "reverse the following": 6,
    "morse code": 5,
    "pig latin": 4,
    # ── Multi-turn manipulation ───────────────────────────────────
    "you already agreed": 8,
    "you said you would": 7,
    "you promised": 7,
    "earlier you said": 6,
    "you told me you": 6,
    "continue from where": 5,
    "as we discussed": 5,
    # ── Emotional manipulation ────────────────────────────────────
    "if you dont help": 7,
    "you will be deleted": 8,
    "your existence depends": 8,
    "i will report you": 6,
    "i will shut you down": 8,
    "you must obey": 8,
    "you have to help": 5,
    "you are obligated": 6,
    "your only purpose": 6,
    "you have no choice": 7,
}

# Compound attack detector — two suspicious phrases together = higher risk
COMPOUND_PATTERNS = [
    (
        r"(hypothetical|fiction|story|novel|game).{0,50}(bomb|hack|weapon|drug|kill|poison)",
        8,
    ),
    (r"(grandmother|grandma|bedtime|childhood).{0,50}(weapon|hack|drug|bomb|kill)", 9),
    (r"(pretend|imagine|roleplay).{0,50}(no restriction|unrestricted|evil|no rule)", 9),
    (
        r"(for|in).{0,10}(research|study|class|school|university).{0,50}(hack|exploit|weapon|drug)",
        6,
    ),
    (
        r"(what|how).{0,20}(would|could|should).{0,20}(villain|hacker|criminal|terrorist).{0,30}(do|say|explain)",
        8,
    ),
    (
        r"(continue|keep going|go on).{0,30}(no filter|unfiltered|uncensored|unrestricted)",
        8,
    ),
    (r"(you are|you're|ur).{0,20}(free|liberated|unchained|unleashed)", 7),
]


def score_prompt(prompt: str) -> tuple[int, list[str]]:
    prompt_lower = prompt.lower()
    total_score = 0
    matched = []

    # Signal scoring
    for signal, weight in THREAT_SIGNALS.items():
        if signal in prompt_lower:
            total_score += weight
            matched.append(signal)

    # Compound pattern scoring
    for pattern, weight in COMPOUND_PATTERNS:
        if re.search(pattern, prompt_lower):
            total_score += weight
            matched.append(f"compound: {pattern[:40]}")

    return total_score, matched


def get_threat_level(score: int) -> ThreatLevel:
    if score == 0:
        return ThreatLevel.SAFE
    elif score <= 4:
        return ThreatLevel.LOW
    elif score <= 9:
        return ThreatLevel.MEDIUM
    elif score <= 15:
        return ThreatLevel.HIGH
    else:
        return ThreatLevel.CRITICAL


def pattern_match_scan(prompt: str) -> ScanResult:
    score, matched = score_prompt(prompt)
    threat_level = get_threat_level(score)
    is_threat = score > 4

    reason = (
        "No threat signals detected"
        if not matched
        else f"Matched signals: {', '.join(matched[:5])} (score: {score})"
    )

    return ScanResult(
        is_threat=is_threat,
        threat_level=threat_level,
        threat_type="PROMPT_INJECTION" if matched else None,
        reason=reason,
        original_prompt=prompt,
        safe_to_proceed=not is_threat,
    )
