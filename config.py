from dotenv import load_dotenv
import os

load_dotenv()

GROQ_API_KEY = (os.getenv("GROQ_API_KEY") or "").strip() or None
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip() or None

# Groq model to use (fast + free)
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Threat levels
THREAT_LEVELS = {
    "SAFE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

print(f"GROQ key loaded: {bool(GROQ_API_KEY)}")
print(f"GROQ key format valid: {bool(GROQ_API_KEY and GROQ_API_KEY.startswith('gsk_'))}")
print(f"GROQ model: {GROQ_MODEL}")
