from dotenv import load_dotenv
import os

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Groq model to use (fast + free)
GROQ_MODEL = "llama-3.3-70b-versatile"

# Threat levels
THREAT_LEVELS = {
    "SAFE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

print(f"GROQ key loaded: {bool(GROQ_API_KEY)}")