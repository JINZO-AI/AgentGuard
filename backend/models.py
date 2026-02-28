"""AgentGuard - Pydantic Models"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    MINIMAL = "minimal"
    LIMITED = "limited"
    HIGH = "high"
    UNACCEPTABLE = "unacceptable"


class RegulationScope(str, Enum):
    EU_AI_ACT = "EU_AI_ACT"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    SOX = "SOX"
    CCPA = "CCPA"


class AgentRegistration(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")
    provider: str = Field(..., pattern="^(openai|anthropic|custom)$")
    model: str = Field(..., min_length=1)
    risk_level: RiskLevel = RiskLevel.MINIMAL
    regulation_scope: List[RegulationScope] = Field(default=[RegulationScope.EU_AI_ACT])
    has_human_oversight: bool = False
    has_qms: bool = False
    has_access_controls: bool = False
    has_encryption: bool = True
    has_policy_docs: bool = False
    has_baa: bool = False
    has_internal_controls: bool = False
    has_retention_policy: bool = False
    has_change_management: bool = False


class ComplianceCheckRequest(BaseModel):
    agent_id: str
    regulation: RegulationScope = RegulationScope.EU_AI_ACT
    days_back: int = Field(default=30, ge=1, le=365)


class ReportRequest(BaseModel):
    agent_id: str
    report_type: str = Field(..., pattern="^(annex_iv|audit_summary|hipaa_audit|sox_controls)$")
    period_days: int = Field(default=30, ge=1, le=365)


class AuditLogEntry(BaseModel):
    agent_id: str
    event_type: str
    prompt_hash: Optional[str] = None
    response_hash: Optional[str] = None
    model: str
    provider: str
    risk_score: float = 0.0
    pii_detected: bool = False
    pii_types: List[str] = []
    compliance_flags: List[Dict] = []
    metadata: Dict[str, Any] = {}
