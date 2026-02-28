# 🛡️ AgentGuard — AI Agent Compliance & Audit Trail System

> **Zero upfront cost. Real recurring revenue. EU AI Act, HIPAA, SOX compliance automation.**

AgentGuard intercepts AI agent API calls, logs them with PII detection and risk scoring, and auto-generates regulatory compliance documentation. Built for the 2026-2030 market gap between "AI agents everywhere" and "compliance requirements for everything."

---

## 🚀 Quick Start (5 minutes)

```bash
git clone https://github.com/you/agentguard
cd agentguard/backend
pip install -r requirements.txt
uvicorn main:app --reload
# Dashboard: open AgentGuard-Dashboard.jsx in claude.ai or deploy to Vercel
```

---

## 🏗️ Architecture

```
Your App → POST /proxy/openai/v1/chat/completions
                    ↓
         AgentGuard Interceptor Middleware
         ├── PII Detection (10 types)
         ├── EU AI Act Risk Classification
         ├── Compliance Flag Generation
         └── Immutable Audit Log (SQLite)
                    ↓
         OpenAI / Anthropic API (transparent proxy)
                    ↓
         Response returned to your app
```

---

## 📁 File Structure

```
agentguard/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── interceptor.py       # AI call interceptor middleware
│   ├── compliance_engine.py # EU AI Act, HIPAA, SOX checking
│   ├── report_generator.py  # Annex IV + audit report generator
│   ├── database.py          # SQLite schema + async queries
│   ├── models.py            # Pydantic request/response models
│   ├── proxy_handler.py     # Transparent AI API proxy
│   ├── requirements.txt
│   ├── .env.example
│   └── routes/
│       ├── agents.py        # Agent registration & management
│       ├── audit.py         # Audit log retrieval
│       ├── compliance.py    # Compliance check endpoints
│       ├── reports.py       # Report generation & download
│       └── dashboard.py     # Dashboard summary stats
├── AgentGuard-Dashboard.jsx # Full React dashboard
└── README.md
```

---

## 🔌 Integration (2 lines of code)

**Before (direct OpenAI call):**
```python
client = OpenAI(api_key="sk-...")
response = client.chat.completions.create(model="gpt-4o-mini", messages=[...])
```

**After (AgentGuard monitored):**
```python
client = OpenAI(
    api_key="sk-...",
    base_url="http://localhost:8000/proxy/openai/v1"  # ← only change
)
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[...],
    extra_headers={"X-Agent-ID": "ag-001"}  # ← your agent ID
)
```

That's it. Every call is now logged, risk-scored, and compliance-checked.

---

## 📋 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agents/register` | Register AI agent |
| GET | `/api/agents/` | List all agents |
| POST | `/proxy/openai/{path}` | Monitored OpenAI proxy |
| POST | `/proxy/anthropic/{path}` | Monitored Anthropic proxy |
| GET | `/api/audit/{agent_id}` | Fetch audit logs |
| GET | `/api/audit/{agent_id}/stats` | Audit statistics |
| POST | `/api/compliance/check` | Run compliance check |
| GET | `/api/compliance/{agent_id}/history` | Compliance history |
| POST | `/api/reports/generate` | Generate report |
| GET | `/api/reports/{id}/download` | Download report |
| GET | `/api/dashboard/summary` | Dashboard data |

---

## ✅ Compliance Coverage

### EU AI Act
- Article 6 — Risk classification (minimal/limited/high/unacceptable)
- Article 9 — Risk management system
- Article 12 — Automatic logging *(this is AgentGuard's core feature)*
- Article 13 — Transparency and documentation
- Article 14 — Human oversight mechanisms
- Article 17 — Quality management
- Annex IV — Technical documentation auto-generation

### HIPAA
- PHI detection and disclosure tracking (45 CFR 164.502)
- Access control verification (45 CFR 164.308)
- Encryption validation (45 CFR 164.312)
- BAA requirement tracking (45 CFR 164.504)

### SOX
- Section 302 — AI decision audit trails
- Section 404 — Internal controls documentation
- Section 802 — 7-year records retention tracking

---

## 💰 Pricing Model (Recommended)

| Tier | Price | Features |
|------|-------|---------|
| **Starter** | €500/month | 1 agent, EU AI Act only, 30-day logs |
| **Growth** | €1,500/month | 5 agents, all regulations, 1-year logs |
| **Enterprise** | €5,000/month | Unlimited agents, custom integrations, SLA |
| **Setup** | €5,000 one-time | Onboarding + Annex IV package |

---

## 🚀 Deployment (Free Tier)

```bash
# Backend → Railway.app (free tier: 500hrs/month)
railway up

# Or Render.com (free tier: spins down after inactivity)
# Set env vars: OPENAI_API_KEY, ANTHROPIC_API_KEY, SECRET_KEY

# Frontend (Dashboard) → Vercel (free tier: unlimited)
vercel --prod
```

---

## 🗺️ 90-Day Roadmap

**Days 1-30:** ✅ Core built (you're here)
- [x] Agent interceptor middleware
- [x] PII detection
- [x] EU AI Act risk classification
- [x] Audit trail database
- [x] Compliance scoring engine
- [x] Annex IV report generator
- [x] React dashboard

**Days 31-60:** Find first customer
- [ ] Deploy to Railway/Render
- [ ] Free audit for 10 EU AI startups
- [ ] Case studies + testimonials
- [ ] LinkedIn/Twitter build-in-public

**Days 61-90:** First €5K
- [ ] Stripe payment integration
- [ ] Email alerts for high-risk events
- [ ] Slack/Teams notifications
- [ ] First paid compliance package

---

## ⚠️ Important Notes

1. This tool generates compliance *documentation* — it is NOT a substitute for qualified legal counsel
2. Content is hashed (SHA-256), never stored in plaintext for privacy
3. Annex IV documents must be reviewed by legal before regulatory submission
4. BAA execution with AI providers (OpenAI, Anthropic) must be done manually

---

*AgentGuard — Built for the 2026-2030 AI compliance market gap*
