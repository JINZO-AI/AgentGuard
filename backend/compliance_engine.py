"""
AgentGuard - Compliance Engine
Maps AI agent behaviors to EU AI Act, HIPAA, SOX, GDPR requirements.
Generates compliance scores and actionable findings.
"""
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

import aiosqlite

logger = logging.getLogger("agentguard.compliance")


class Regulation(str, Enum):
    EU_AI_ACT = "EU_AI_ACT"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    SOX = "SOX"
    CCPA = "CCPA"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceFinding:
    code: str
    title: str
    description: str
    severity: Severity
    regulation: Regulation
    article_reference: str
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    score_impact: float = 0.0


@dataclass
class ComplianceReport:
    agent_id: str
    regulation: Regulation
    check_date: str
    period_start: str
    period_end: str
    overall_score: float
    grade: str
    findings: List[ComplianceFinding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    summary: str = ""
    total_interactions: int = 0
    flagged_interactions: int = 0
    pii_exposures: int = 0
    high_risk_interactions: int = 0


# EU AI Act compliance rules
EU_AI_ACT_RULES = [
    {
        "code": "EUAIA-ART13-001",
        "title": "Transparency & Documentation",
        "description": "High-risk AI systems must provide instructions and documentation (Article 13)",
        "article": "Article 13",
        "check": "has_documentation",
        "severity": Severity.HIGH,
        "score_weight": 0.15
    },
    {
        "code": "EUAIA-ART14-001",
        "title": "Human Oversight Mechanisms",
        "description": "High-risk AI must enable human oversight and intervention (Article 14)",
        "article": "Article 14",
        "check": "has_human_oversight",
        "severity": Severity.HIGH,
        "score_weight": 0.15
    },
    {
        "code": "EUAIA-ART17-001",
        "title": "Quality Management System",
        "description": "Providers of high-risk AI must maintain quality management system (Article 17)",
        "article": "Article 17",
        "check": "has_qms",
        "severity": Severity.MEDIUM,
        "score_weight": 0.10
    },
    {
        "code": "EUAIA-ART9-001",
        "title": "Risk Management System",
        "description": "Providers must establish continuous risk management (Article 9)",
        "article": "Article 9",
        "check": "has_risk_management",
        "severity": Severity.HIGH,
        "score_weight": 0.15
    },
    {
        "code": "EUAIA-ANNIV-001",
        "title": "Technical Documentation (Annex IV)",
        "description": "Detailed technical documentation must be maintained and available for audit",
        "article": "Annex IV",
        "check": "has_technical_docs",
        "severity": Severity.HIGH,
        "score_weight": 0.20
    },
    {
        "code": "EUAIA-ART12-001",
        "title": "Record Keeping & Audit Logs",
        "description": "High-risk AI must keep automatic logs to ensure traceability (Article 12)",
        "article": "Article 12",
        "check": "has_audit_logs",
        "severity": Severity.CRITICAL,
        "score_weight": 0.25
    },
]

HIPAA_RULES = [
    {
        "code": "HIPAA-164-502",
        "title": "PHI Disclosure Tracking",
        "description": "All PHI access and disclosures must be logged and traceable",
        "article": "45 CFR 164.502",
        "check": "phi_disclosure_tracking",
        "severity": Severity.CRITICAL,
        "score_weight": 0.30
    },
    {
        "code": "HIPAA-164-308",
        "title": "Access Controls",
        "description": "AI systems accessing PHI must implement access controls",
        "article": "45 CFR 164.308(a)(4)",
        "check": "has_access_controls",
        "severity": Severity.HIGH,
        "score_weight": 0.25
    },
    {
        "code": "HIPAA-164-312",
        "title": "Encryption in Transit",
        "description": "All PHI transmitted via AI agent must be encrypted",
        "article": "45 CFR 164.312(e)(1)",
        "check": "has_encryption",
        "severity": Severity.HIGH,
        "score_weight": 0.20
    },
    {
        "code": "HIPAA-164-316",
        "title": "Policy Documentation",
        "description": "Policies governing AI use with PHI must be documented",
        "article": "45 CFR 164.316",
        "check": "has_policy_docs",
        "severity": Severity.MEDIUM,
        "score_weight": 0.15
    },
    {
        "code": "HIPAA-BAA",
        "title": "Business Associate Agreement",
        "description": "BAA required with AI model providers processing PHI",
        "article": "45 CFR 164.504(e)",
        "check": "has_baa",
        "severity": Severity.CRITICAL,
        "score_weight": 0.10
    },
]

SOX_RULES = [
    {
        "code": "SOX-302-001",
        "title": "AI Decision Auditability",
        "description": "AI-assisted financial decisions must be auditable (Section 302)",
        "article": "SOX Section 302",
        "check": "has_decision_audit_trail",
        "severity": Severity.CRITICAL,
        "score_weight": 0.35
    },
    {
        "code": "SOX-404-001",
        "title": "Internal Controls Documentation",
        "description": "Internal controls over AI use in financial reporting (Section 404)",
        "article": "SOX Section 404",
        "check": "has_internal_controls",
        "severity": Severity.HIGH,
        "score_weight": 0.30
    },
    {
        "code": "SOX-802-001",
        "title": "Records Retention",
        "description": "AI interaction records must be retained for 7 years",
        "article": "SOX Section 802",
        "check": "has_retention_policy",
        "severity": Severity.HIGH,
        "score_weight": 0.20
    },
    {
        "code": "SOX-ICFR-001",
        "title": "Change Management",
        "description": "AI model changes must follow documented change control process",
        "article": "PCAOB AS 2201",
        "check": "has_change_management",
        "severity": Severity.MEDIUM,
        "score_weight": 0.15
    },
]

REGULATION_RULES = {
    Regulation.EU_AI_ACT: EU_AI_ACT_RULES,
    Regulation.HIPAA: HIPAA_RULES,
    Regulation.SOX: SOX_RULES,
}


class ComplianceEngine:
    """
    Core compliance checking engine.
    Analyzes audit logs and agent configuration to produce compliance scores.
    """
    
    RECOMMENDATIONS_LIBRARY = {
        "has_audit_logs": "✅ Implement comprehensive audit logging via AgentGuard middleware",
        "has_documentation": "📄 Generate technical documentation using AgentGuard report generator",
        "has_human_oversight": "👤 Add human-in-the-loop review for high-risk decisions; implement override mechanisms",
        "has_qms": "📋 Document your quality management system including testing, monitoring, and improvement cycles",
        "has_risk_management": "⚠️ Establish continuous risk assessment; use AgentGuard risk scoring",
        "has_technical_docs": "🔧 Auto-generate Annex IV documentation using AgentGuard report generator",
        "phi_disclosure_tracking": "🏥 Enable HIPAA-specific logging in AgentGuard; track all PHI field accesses",
        "has_access_controls": "🔐 Implement role-based access control; document in system architecture",
        "has_encryption": "🔒 Ensure all AI API calls use TLS 1.2+; implement field-level encryption for PHI",
        "has_policy_docs": "📝 Create and document AI governance policies; review quarterly",
        "has_baa": "📃 Execute Business Associate Agreements with OpenAI/Anthropic before using PHI",
        "has_decision_audit_trail": "📊 Log all AI-assisted financial decisions with inputs, outputs, and approver",
        "has_internal_controls": "🏛️ Document AI controls in your SOX compliance framework",
        "has_retention_policy": "🗄️ Configure 7-year log retention in AgentGuard storage settings",
        "has_change_management": "🔄 Implement model version tracking; document each model update",
    }
    
    async def run_compliance_check(
        self,
        agent_id: str,
        regulation: Regulation,
        days_back: int = 30
    ) -> ComplianceReport:
        """Run a full compliance check for an agent against a regulation."""
        
        period_end = datetime.utcnow()
        period_start = period_end - timedelta(days=days_back)
        
        # Fetch audit logs
        stats = await self._get_audit_stats(agent_id, period_start, period_end)
        agent_config = await self._get_agent_config(agent_id)
        
        # Get rules for this regulation
        rules = REGULATION_RULES.get(regulation, [])
        
        findings = []
        total_score = 0.0
        max_score = sum(r["score_weight"] for r in rules)
        
        for rule in rules:
            finding, score_earned = await self._evaluate_rule(
                rule, agent_id, stats, agent_config, regulation
            )
            if finding:
                findings.append(finding)
                # Non-compliance means score loss
                total_score -= rule["score_weight"] * finding.score_impact
            else:
                total_score += rule["score_weight"]
        
        # Normalize to 0-100
        base_score = (total_score / max_score) * 100 if max_score > 0 else 0
        overall_score = max(0, min(100, base_score))
        
        # Generate grade
        grade = self._calculate_grade(overall_score)
        
        # Build recommendations
        recommendations = self._generate_recommendations(findings, stats)
        
        report = ComplianceReport(
            agent_id=agent_id,
            regulation=regulation,
            check_date=datetime.utcnow().isoformat(),
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
            overall_score=round(overall_score, 1),
            grade=grade,
            findings=findings,
            recommendations=recommendations,
            total_interactions=stats.get("total", 0),
            flagged_interactions=stats.get("flagged", 0),
            pii_exposures=stats.get("pii_count", 0),
            high_risk_interactions=stats.get("high_risk", 0),
            summary=self._generate_summary(overall_score, findings, stats, regulation)
        )
        
        # Save to database
        await self._save_compliance_check(report)
        
        return report
    
    async def _get_audit_stats(
        self, agent_id: str, period_start: datetime, period_end: datetime
    ) -> Dict:
        """Aggregate audit log statistics for the period."""
        stats = {
            "total": 0, "flagged": 0, "pii_count": 0,
            "high_risk": 0, "avg_risk_score": 0.0,
            "has_logs": False, "log_days": set()
        }
        
        try:
            async with aiosqlite.connect("agentguard.db") as db:
                db.row_factory = aiosqlite.Row
                
                cursor = await db.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(pii_detected) as pii_count,
                        SUM(CASE WHEN risk_score > 0.6 THEN 1 ELSE 0 END) as high_risk,
                        SUM(CASE WHEN compliance_flags != '[]' THEN 1 ELSE 0 END) as flagged,
                        AVG(risk_score) as avg_risk_score,
                        MIN(timestamp) as first_log,
                        MAX(timestamp) as last_log,
                        COUNT(DISTINCT DATE(timestamp)) as log_days
                    FROM audit_logs
                    WHERE agent_id = ?
                    AND timestamp BETWEEN ? AND ?
                """, (agent_id, period_start.isoformat(), period_end.isoformat()))
                
                row = await cursor.fetchone()
                if row and row["total"]:
                    stats["total"] = row["total"] or 0
                    stats["pii_count"] = row["pii_count"] or 0
                    stats["high_risk"] = row["high_risk"] or 0
                    stats["flagged"] = row["flagged"] or 0
                    stats["avg_risk_score"] = row["avg_risk_score"] or 0.0
                    stats["log_days"] = row["log_days"] or 0
                    stats["has_logs"] = stats["total"] > 0
        
        except Exception as e:
            logger.error(f"Failed to get audit stats: {e}")
        
        return stats
    
    async def _get_agent_config(self, agent_id: str) -> Dict:
        """Get agent configuration from database."""
        try:
            async with aiosqlite.connect("agentguard.db") as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(
                    "SELECT * FROM agents WHERE id = ?", (agent_id,)
                )
                row = await cursor.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            logger.error(f"Failed to get agent config: {e}")
        return {}
    
    async def _evaluate_rule(
        self, rule: Dict, agent_id: str, stats: Dict,
        agent_config: Dict, regulation: Regulation
    ) -> Tuple[Optional[ComplianceFinding], float]:
        """Evaluate a single compliance rule. Returns (finding_if_failed, score_impact)."""
        
        check = rule["check"]
        passed = False
        evidence = []
        
        if check == "has_audit_logs":
            passed = stats.get("has_logs", False) and stats.get("total", 0) > 0
            evidence = [f"Total logged interactions: {stats.get('total', 0)}"]
        
        elif check == "has_documentation":
            # Check if technical docs have been generated
            try:
                async with aiosqlite.connect("agentguard.db") as db:
                    cursor = await db.execute(
                        "SELECT COUNT(*) as c FROM reports WHERE agent_id = ? AND report_type = 'technical_docs'",
                        (agent_id,)
                    )
                    row = await cursor.fetchone()
                    passed = (row[0] > 0) if row else False
            except:
                passed = False
        
        elif check == "has_human_oversight":
            # Check agent config for human oversight flag
            passed = agent_config.get("has_human_oversight", False)
        
        elif check == "has_qms":
            passed = agent_config.get("has_qms", False)
        
        elif check == "has_risk_management":
            # We ARE the risk management system - check if risk scores are being computed
            passed = stats.get("has_logs", False)
            evidence = [f"Risk scoring active: avg score = {stats.get('avg_risk_score', 0):.2f}"]
        
        elif check == "has_technical_docs":
            try:
                async with aiosqlite.connect("agentguard.db") as db:
                    cursor = await db.execute(
                        "SELECT COUNT(*) as c FROM reports WHERE agent_id = ?",
                        (agent_id,)
                    )
                    row = await cursor.fetchone()
                    passed = (row[0] > 0) if row else False
            except:
                passed = False
        
        elif check == "phi_disclosure_tracking":
            passed = stats.get("has_logs", False)
            if passed and stats.get("pii_count", 0) > 0:
                evidence = [f"PHI exposures detected and logged: {stats['pii_count']}"]
        
        elif check in ["has_access_controls", "has_encryption", "has_policy_docs",
                        "has_baa", "has_internal_controls", "has_retention_policy",
                        "has_change_management"]:
            # These require manual attestation in agent config
            passed = agent_config.get(check, False)
        
        elif check == "has_decision_audit_trail":
            passed = stats.get("has_logs", False) and stats.get("total", 0) > 0
        
        else:
            passed = False
        
        if not passed:
            finding = ComplianceFinding(
                code=rule["code"],
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                regulation=regulation,
                article_reference=rule["article"],
                evidence=evidence,
                remediation=self.RECOMMENDATIONS_LIBRARY.get(check, "Review and remediate manually"),
                score_impact=1.0
            )
            return finding, 1.0
        
        return None, 0.0
    
    def _calculate_grade(self, score: float) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def _generate_recommendations(
        self, findings: List[ComplianceFinding], stats: Dict
    ) -> List[str]:
        recs = []
        
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        
        if critical:
            recs.append(f"🚨 URGENT: Resolve {len(critical)} critical findings immediately before enterprise deployment")
        if high:
            recs.append(f"⚠️ Address {len(high)} high-severity gaps within 30 days")
        
        if stats.get("pii_count", 0) > 0:
            recs.append(f"🔐 Implement PII masking: {stats['pii_count']} PII exposures detected in AI interactions")
        
        if stats.get("high_risk", 0) > 0:
            recs.append(f"⚡ Review {stats['high_risk']} high-risk interactions for appropriate human oversight")
        
        recs.append("📊 Schedule monthly compliance reviews using AgentGuard automated scanning")
        recs.append("🎓 Train team on EU AI Act obligations specific to your use case")
        recs.append("📋 Prepare Annex IV technical documentation for regulatory authority review")
        
        return recs
    
    def _generate_summary(
        self, score: float, findings: List[ComplianceFinding],
        stats: Dict, regulation: Regulation
    ) -> str:
        critical_count = len([f for f in findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in findings if f.severity == Severity.HIGH])
        
        if score >= 80:
            status = "substantially compliant"
            action = "Minor gaps identified. Focus on closing remaining findings."
        elif score >= 60:
            status = "partially compliant"
            action = "Significant gaps require attention before audit or enterprise sales."
        else:
            status = "non-compliant"
            action = "Immediate action required. Do not deploy to regulated environments."
        
        return (
            f"This AI agent is currently {status} with {regulation.value} requirements, "
            f"achieving a compliance score of {score:.1f}/100. "
            f"Analysis of {stats.get('total', 0)} logged interactions identified "
            f"{len(findings)} findings ({critical_count} critical, {high_count} high severity). "
            f"{action}"
        )
    
    async def _save_compliance_check(self, report: ComplianceReport):
        """Save compliance check results to database."""
        import uuid
        try:
            async with aiosqlite.connect("agentguard.db") as db:
                await db.execute("""
                    INSERT INTO compliance_checks 
                    (id, agent_id, check_date, regulation, overall_score, findings, recommendations, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    report.agent_id,
                    report.check_date,
                    report.regulation.value,
                    report.overall_score,
                    json.dumps([{
                        "code": f.code, "title": f.title, "severity": f.severity.value,
                        "description": f.description, "article": f.article_reference,
                        "remediation": f.remediation
                    } for f in report.findings]),
                    json.dumps(report.recommendations),
                    "completed"
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to save compliance check: {e}")
