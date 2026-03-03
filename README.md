# 🛡️ AgentGuard

AI agent compliance and audit trail system. Acts as a transparent reverse proxy in front of AI providers — intercepting every call to scan for PII, score regulatory risk, and write an immutable audit log.

---

## 🏗️ Architecture

```
Your App
    │
    ▼
POST /proxy/openai/v1/...  (or /anthropic, /groq)
    │
    ├── 🔍 AgentInterceptorMiddleware (Starlette)
    │     ├── PIIDetector       — regex scan, 10 PII types
    │     ├── RiskClassifier    — EU AI Act keyword classification
    │     ├── ComplianceFlagger — maps violations to regulatory articles
    │     └── SHA-256 hash → async write to SQLite audit_logs
    │
    ▼
Provider API (OpenAI / Anthropic / Groq)
    │
    ▼
Response returned to your app unchanged
```

Four SQLite tables: `agents`, `audit_logs`, `compliance_checks`, `reports`.  
Raw prompts and responses are **never stored** — only SHA-256 hashes.

---

## ✅ What it does

- 🔀 Proxies calls to OpenAI, Anthropic, and Groq with no changes to the response
- 🔎 Scans every prompt and response for 10 PII types (email, SSN, credit card, IBAN, medical ID, etc.) using regex
- ⚖️ Classifies interactions against EU AI Act risk levels (minimal / limited / high / unacceptable)
- 📋 Writes a SHA-256 hashed, immutable audit log to SQLite — raw content is never stored
- 📊 Scores compliance against EU AI Act, HIPAA, and SOX mapped to specific regulatory articles
- 📄 Auto-generates EU AI Act Annex IV technical documentation in Markdown
- 🖥️ React dashboard included — currently uses hardcoded mock data

**Tested and confirmed working:** PII detection (SSN, email, phone), OpenAI and Groq proxying, audit log writing, compliance flag generation with GDPR/EU AI Act article mapping, risk scoring.

---

## 🚀 Quick Start

```bash
git clone https://github.com/JINZO-AI/AgentGuard
cd AgentGuard/backend
pip install -r requirements.txt
cp .env.example .env   # add your own API keys — never commit .env
python main.py
# API docs: http://localhost:8000/api/docs
```

## 🔌 Integration

```python
# Before
client = OpenAI(api_key="sk-...")

# After — one line change
client = OpenAI(
    api_key="sk-...",
    base_url="http://localhost:8000/proxy/openai/v1"
)

# Tag calls with a registered agent ID
extra_headers={"X-Agent-ID": "your-agent-id"}
```

Groq works the same way via `/proxy/groq/v1`.

---

## 🛠️ Stack

Python · FastAPI · Starlette middleware · aiosqlite · Pydantic v2 · httpx · React 18

---

## ⚠️ Known Limitations

- No authentication on API endpoints
- CORS is set to `allow_origins=["*"]`
- DB path is hardcoded in routes — `DATABASE_URL` in `.env` is not used
- PII detection is regex only — false positives and negatives are expected
- `AgentRegistration` validates provider as `openai|anthropic|custom` but the proxy also supports Groq
- No test suite
- Dashboard displays mock data, not live API data

---

## 📜 Disclaimer

AgentGuard generates compliance evidence and documentation for informational purposes only. It is not a substitute for qualified legal counsel. Annex IV documents should be reviewed by a compliance officer before any regulatory submission. Business Associate Agreements with AI providers must be executed separately.
