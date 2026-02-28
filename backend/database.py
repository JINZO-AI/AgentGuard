"""
AgentGuard - Database Layer
Uses SQLite for local dev, Supabase-compatible schema for production
"""
import aiosqlite
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("agentguard.db")
DB_PATH = Path("agentguard.db")

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    risk_level TEXT DEFAULT 'minimal',
    regulation_scope TEXT DEFAULT '[]',
    api_key_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    session_id TEXT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    prompt_hash TEXT,
    prompt_tokens INTEGER,
    response_hash TEXT,
    response_tokens INTEGER,
    model TEXT,
    provider TEXT,
    risk_score REAL DEFAULT 0.0,
    pii_detected INTEGER DEFAULT 0,
    pii_types TEXT DEFAULT '[]',
    tool_calls TEXT DEFAULT '[]',
    compliance_flags TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS compliance_checks (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    check_date TEXT NOT NULL,
    regulation TEXT NOT NULL,
    overall_score REAL NOT NULL,
    findings TEXT DEFAULT '[]',
    recommendations TEXT DEFAULT '[]',
    status TEXT DEFAULT 'pending',
    report_path TEXT,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    report_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    period_start TEXT,
    period_end TEXT,
    file_path TEXT,
    status TEXT DEFAULT 'generating',
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_agent ON audit_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_compliance_agent ON compliance_checks(agent_id);
"""


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_TABLES)
        await db.commit()
    logger.info(f"Database initialized at {DB_PATH}")


async def get_db():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        yield db
