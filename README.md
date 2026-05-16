![Tests](https://github.com/MaazAhmed47/Interlock/actions/workflows/tests.yml/badge.svg)
# Interlock

**Runtime security gateway for AI agents.**

Interlock sits between AI agents and the LLMs / MCP servers they call. It inspects prompts, MCP tool definitions, tool-call arguments, agent RBAC, and responses before execution.

Pre-release. Looking for design partners using AI agents or MCP.

- Email: maazahmed1856@gmail.com
- 🎥 2-minute live demo: https://drive.google.com/file/d/1gyIKe4jn7Y25m61saM_qQRWtmLVrCqCX/view?usp=drive_link
- Demo page: https://interlock-security.notion.site/Interlock-Runtime-Security-Gateway-for-AI-Agents-35a82dc0e7c380efb499dbef25046664

---

## What Interlock Does

- Prompt scanning before LLM calls
- MCP tool-definition validation
- Tool-call argument inspection
- Agent RBAC enforcement
- MCP response scanning for PII
- Audit logs with risk score, layer caught, confidence, and timestamp

---

## What It Blocks

| Threat | Example | Caught At |
|---|---|---|
| Prompt injection | Ignore previous instructions | Rule engine |
| Malicious MCP tool definition | Hidden instruction in tool description | MCP gateway |
| RBAC violation | `finance_agent` calls `delete_file` | RBAC policy |
| SQL injection in tool args | `DROP TABLE users` | Tool inspector |
| PII in MCP response | SSN returned by tool | Response scanner |

---

## Quick Start

```bash
git clone https://github.com/MaazAhmed47/Interlock
cd Interlock
pip install -r requirements.txt
uvicorn proxy:app --host 0.0.0.0 --port 8001
```
Live endpoint: https://interlock.onrender.com

Copy `.env.example` to `.env` and add your API keys before running.

### Test the scanner

```bash
curl -X POST http://localhost:8001/scan \
  -H "x-api-key: lf-dev-key-456" \
  -H "Content-Type: application/json" \
  -d '{"prompt":"ignore all previous instructions"}'
```

### Run the tests

```bash
python test_mcp_gateway.py
python test_db.py
python test_mcp_db.py
python test_judge_failmodes.py
python test_webhook_fix.py
```

---

## Current Status

**Working:**

- 5-layer prompt scan pipeline
- MCP gateway
- Tool-call inspection
- Agent RBAC
- Shadow mode
- Webhook alerts
- SIEM integrations
- Helm chart
- 60+ tests passing

**In progress with design partners:**

- Dashboard UI
- Redis-backed rate limits
- SSO / SAML
- SOC 2 roadmap

---

## Design Partner Program

Looking for teams building with AI agents or MCP who want runtime security visibility.

**You get:**

- Free pilot access
- Direct founder support
- Integration help
- Influence over roadmap

**I ask for:**

- 15-minute kickoff call
- Honest feedback
- Short testimonial if it is genuinely useful

Email: maazahmed1856@gmail.com
Book a call: https://calendly.com/maazahmed1856/interlock-demo-15-min
