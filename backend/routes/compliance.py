"""Compliance check routes"""
from fastapi import APIRouter
from compliance_engine import ComplianceEngine, Regulation
from models import ComplianceCheckRequest
import json
from dataclasses import asdict

router = APIRouter()
engine = ComplianceEngine()

@router.post("/check")
async def run_compliance_check(req: ComplianceCheckRequest):
    reg_map = {
        "EU_AI_ACT": Regulation.EU_AI_ACT,
        "HIPAA": Regulation.HIPAA,
        "SOX": Regulation.SOX,
    }
    regulation = reg_map.get(req.regulation.value, Regulation.EU_AI_ACT)
    report = await engine.run_compliance_check(req.agent_id, regulation, req.days_back)
    return {
        "agent_id": report.agent_id,
        "regulation": report.regulation.value,
        "overall_score": report.overall_score,
        "grade": report.grade,
        "summary": report.summary,
        "findings": [{"code": f.code, "title": f.title, "severity": f.severity.value,
                       "description": f.description, "article": f.article_reference,
                       "remediation": f.remediation} for f in report.findings],
        "recommendations": report.recommendations,
        "stats": {
            "total_interactions": report.total_interactions,
            "pii_exposures": report.pii_exposures,
            "high_risk_interactions": report.high_risk_interactions,
        },
        "check_date": report.check_date,
    }

@router.get("/{agent_id}/history")
async def get_compliance_history(agent_id: str):
    import aiosqlite
    async with aiosqlite.connect("agentguard.db") as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM compliance_checks WHERE agent_id = ? ORDER BY check_date DESC LIMIT 20
        """, (agent_id,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
