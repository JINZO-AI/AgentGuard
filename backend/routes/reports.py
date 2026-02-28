"""Report generation routes"""
from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import FileResponse
from report_generator import ReportGenerator
from models import ReportRequest
import uuid, json
import aiosqlite
from datetime import datetime
from pathlib import Path

router = APIRouter()
generator = ReportGenerator()

@router.post("/generate")
async def generate_report(req: ReportRequest, background_tasks: BackgroundTasks):
    report_id = str(uuid.uuid4())
    async with aiosqlite.connect("agentguard.db") as db:
        await db.execute("""
            INSERT INTO reports (id, agent_id, report_type, created_at, status)
            VALUES (?, ?, ?, ?, 'generating')
        """, (report_id, req.agent_id, req.report_type, datetime.utcnow().isoformat()))
        await db.commit()
    background_tasks.add_task(_generate_report_bg, report_id, req)
    return {"report_id": report_id, "status": "generating", "message": "Report generation started"}

async def _generate_report_bg(report_id: str, req: ReportRequest):
    try:
        # Get compliance data
        async with aiosqlite.connect("agentguard.db") as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM agents WHERE id = ?", (req.agent_id,))
            agent = dict(await cursor.fetchone() or {})
            cursor = await db.execute("""
                SELECT * FROM compliance_checks WHERE agent_id = ? ORDER BY check_date DESC LIMIT 1
            """, (req.agent_id,))
            check_row = await cursor.fetchone()
            compliance_data = dict(check_row) if check_row else {}
        
        if compliance_data.get("findings"):
            compliance_data["findings"] = json.loads(compliance_data["findings"])
        if compliance_data.get("recommendations"):
            compliance_data["recommendations"] = json.loads(compliance_data["recommendations"])
        compliance_data.update({
            "agent_name": agent.get("name", "AI Agent"),
            "description": agent.get("description", ""),
            "provider": agent.get("provider", "openai"),
            "model": agent.get("model", "gpt-4o-mini"),
            "risk_level": agent.get("risk_level", "limited"),
        })
        
        if req.report_type == "annex_iv":
            filepath = await generator.generate_annex_iv(req.agent_id, compliance_data)
        else:
            filepath = await generator.generate_audit_summary(req.agent_id, req.period_days)
        
        async with aiosqlite.connect("agentguard.db") as db:
            await db.execute("""
                UPDATE reports SET status = 'completed', file_path = ? WHERE id = ?
            """, (filepath, report_id))
            await db.commit()
    except Exception as e:
        async with aiosqlite.connect("agentguard.db") as db:
            await db.execute("UPDATE reports SET status = 'failed' WHERE id = ?", (report_id,))
            await db.commit()

@router.get("/{report_id}/download")
async def download_report(report_id: str):
    async with aiosqlite.connect("agentguard.db") as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = await cursor.fetchone()
        if not row:
            from fastapi import HTTPException
            raise HTTPException(404, "Report not found")
        report = dict(row)
    
    if report["status"] != "completed":
        return {"status": report["status"], "message": "Report not ready yet"}
    
    filepath = Path(report["file_path"])
    if not filepath.exists():
        from fastapi import HTTPException
        raise HTTPException(404, "Report file not found")
    
    return FileResponse(str(filepath), filename=filepath.name, media_type="text/markdown")
