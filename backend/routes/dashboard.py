"""Dashboard summary routes"""
from fastapi import APIRouter
import aiosqlite
import json

router = APIRouter()

@router.get("/summary")
async def get_dashboard_summary():
    async with aiosqlite.connect("agentguard.db") as db:
        db.row_factory = aiosqlite.Row
        
        cursor = await db.execute("SELECT COUNT(*) as c FROM agents WHERE is_active = 1")
        agents_count = (await cursor.fetchone())["c"]
        
        cursor = await db.execute("""
            SELECT COUNT(*) as total,
                   SUM(pii_detected) as pii,
                   SUM(CASE WHEN risk_score > 0.6 THEN 1 ELSE 0 END) as high_risk,
                   AVG(risk_score) as avg_risk
            FROM audit_logs
        """)
        row = dict(await cursor.fetchone())
        
        cursor = await db.execute("""
            SELECT AVG(overall_score) as avg_score FROM compliance_checks
        """)
        score_row = await cursor.fetchone()
        avg_score = score_row["avg_score"] if score_row and score_row["avg_score"] else 0
        
        cursor = await db.execute("""
            SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10
        """)
        recent = [dict(r) for r in await cursor.fetchall()]
        for r in recent:
            r["compliance_flags"] = json.loads(r.get("compliance_flags", "[]"))
            r["pii_types"] = json.loads(r.get("pii_types", "[]"))
    
    return {
        "agents_count": agents_count,
        "total_interactions": row.get("total", 0) or 0,
        "pii_exposures": row.get("pii", 0) or 0,
        "high_risk_count": row.get("high_risk", 0) or 0,
        "avg_risk_score": round(row.get("avg_risk", 0) or 0, 2),
        "avg_compliance_score": round(avg_score, 1),
        "recent_events": recent
    }
