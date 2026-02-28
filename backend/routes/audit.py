"""Audit log routes"""
from fastapi import APIRouter, Query
import aiosqlite
import json

router = APIRouter()

@router.get("/{agent_id}")
async def get_audit_logs(
    agent_id: str,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    min_risk: float = 0.0
):
    async with aiosqlite.connect("agentguard.db") as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM audit_logs 
            WHERE agent_id = ? AND risk_score >= ?
            ORDER BY timestamp DESC LIMIT ? OFFSET ?
        """, (agent_id, min_risk, limit, offset))
        rows = await cursor.fetchall()
        logs = []
        for r in rows:
            d = dict(r)
            d["pii_types"] = json.loads(d.get("pii_types", "[]"))
            d["compliance_flags"] = json.loads(d.get("compliance_flags", "[]"))
            d["tool_calls"] = json.loads(d.get("tool_calls", "[]"))
            logs.append(d)
        return logs

@router.get("/{agent_id}/stats")
async def get_audit_stats(agent_id: str):
    async with aiosqlite.connect("agentguard.db") as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT COUNT(*) as total,
                   SUM(pii_detected) as pii_count,
                   SUM(CASE WHEN risk_score > 0.6 THEN 1 ELSE 0 END) as high_risk,
                   AVG(risk_score) as avg_risk,
                   MAX(timestamp) as last_seen
            FROM audit_logs WHERE agent_id = ?
        """, (agent_id,))
        row = await cursor.fetchone()
        return dict(row) if row else {}
