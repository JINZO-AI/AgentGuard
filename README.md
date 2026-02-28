# 🛡️ AgentGuard 

I built AgentGuard because everyone is talking about AI agents, but no one is talking about how to actually make them "legal" for real companies to use. If you're building an agent in 2026, you're going to hit a wall with things like the **EU AI Act**, **HIPAA**, or **SOX** compliance.

AgentGuard is a middleware "safety net" that sits between your agent and the LLM (OpenAI/Anthropic). It watches the traffic, catches sensitive data (PII) before it leaks, and automatically builds the audit logs that lawyers and auditors actually care about.

## ✨ What it actually does
* **The "One-Line" Proxy:** You don't have to rewrite your whole app. Just change the `base_url` in your OpenAI/Anthropic client to point to AgentGuard.
* **PII Sniffer:** Automatically flags emails, credit cards, and SSNs in prompts or responses.
* **Legal Report Bot:** It generates those annoying **Annex IV** technical docs required by the EU AI Act so you don't have to write them by hand.
* **Risk Scoring:** It gives every interaction a "risk score" based on current regulations.

## 🚀 Tech Stack
I kept this lean and free-tier friendly:
* **FastAPI** (The backbone)
* **SQLite** (Local storage, super easy to move to Supabase later)
* **httpx** (For the proxy logic)
* **Jinja2** (For generating the compliance reports)

## 🛠️ Quick Setup
1. **Clone it:** `git clone https://github.com/yourname/agentguard.git`
2. **Install:** `pip install -r requirements.txt`
3. **Set your keys:** Create a `.env` file and add your `OPENAI_API_KEY`.
4. **Run it:** `uvicorn main:app --reload`

## 🔌 How to use it
In your agent code, just swap your base URL. It takes about 10 seconds:

```python
from openai import OpenAI

client = OpenAI(
    api_key="your-key",
    base_url="http://localhost:8000/proxy/openai/v1" # This is the magic line
)

# Now every call is automatically logged and checked for compliance
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Analyze these customer records."}],
    extra_headers={"X-Agent-ID": "finance-bot-01"} 
)
