"""Agent management routes"""
import uuid
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
import aiosqlite
from models import AgentRegistration

router = APIRouter()

@router.post("/register")
async def register_agent(agent: AgentRegistration):
    agent_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect("agentguard.db") as db:
        await db.execute("""
            INSERT INTO agents (id, name, description, provider, model, risk_level,
                regulation_scope, created_at, updated_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (agent_id, agent.name, agent.description, agent.provider, agent.model,
              agent.risk_level.value, json.dumps([r.value for r in agent.regulation_scope]),
              now, now))
        await db.commit()
    return {"id": agent_id, "api_key_header": "X-Agent-ID", "api_key_value": agent_id,
            "message": "Add 'X-Agent-ID: {id}' header to all proxied AI calls"}

@router.get("/")
async def list_agents():
    async with aiosqlite.connect("agentguard.db") as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM agents WHERE is_active = 1 ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    async with aiosqlite.connect("agentguard.db") as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Agent not found")
        return dict(row)

@router.delete("/{agent_id}")
async def deactivate_agent(agent_id: str):
    async with aiosqlite.connect("agentguard.db") as db:
        await db.execute("UPDATE agents SET is_active = 0 WHERE id = ?", (agent_id,))
        await db.commit()
    return {"status": "deactivated"}
