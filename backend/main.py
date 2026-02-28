"""
AgentGuard - AI Agent Compliance & Audit Trail System
FastAPI Backend - Main Application Entry Point
"""

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from contextlib import asynccontextmanager
import uvicorn
import logging
from datetime import datetime

from database import init_db
from interceptor import AgentInterceptorMiddleware
from models import AgentRegistration, ComplianceCheckRequest, ReportRequest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("agentguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡️  AgentGuard starting up...")
    await init_db()
    logger.info("✅ Database initialized")
    yield
    logger.info("🛑 AgentGuard shutting down...")


app = FastAPI(
    title="AgentGuard API",
    description="AI Agent Compliance & Audit Trail System for EU AI Act, HIPAA, SOX",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://your-domain.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(AgentInterceptorMiddleware)

from routes import agents, audit, compliance, reports, dashboard
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(audit.router, prefix="/api/audit", tags=["Audit Logs"])
app.include_router(compliance.router, prefix="/api/compliance", tags=["Compliance"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])


@app.get("/")
async def root():
    return {"service": "AgentGuard", "version": "1.0.0", "status": "operational",
            "timestamp": datetime.utcnow().isoformat()}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
