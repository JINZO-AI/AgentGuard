"""
AgentGuard - Agent Interceptor Middleware
Intercepts all AI API calls to log, analyze, and classify for compliance.
Supports OpenAI, Anthropic Claude, and custom agent endpoints.
"""

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime
from typing import Dict, List, Tuple, Optional

import aiosqlite
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("agentguard.interceptor")

# PII Detection patterns
PII_PATTERNS = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ssn": r"\b(?!219-09-9999|078-05-1120)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "iban": r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "date_of_birth": r"\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b",
    "passport": r"\b[A-Z]{1,2}\d{6,9}\b",
    "medical_id": r"\b(NPI|MRN|DEA)[\s:#-]?\d{6,10}\b",
    "financial_account": r"\b\d{8,17}\b",
}

# EU AI Act risk keywords
HIGH_RISK_KEYWORDS = [
    "credit score",
    "loan decision",
    "employment",
    "hiring",
    "termination",
    "medical diagnosis",
    "treatment recommendation",
    "law enforcement",
    "biometric",
    "facial recognition",
    "emotion recognition",
    "critical infrastructure",
    "educational assessment",
    "border control",
    "asylum",
    "benefits eligibility",
]

PROHIBITED_KEYWORDS = [
    "social scoring",
    "mass surveillance",
    "subliminal manipulation",
    "exploit vulnerabilities",
    "real-time biometric public spaces",
]


class PIIDetector:
    """Detects Personally Identifiable Information in text."""

    @staticmethod
    def scan(text: str) -> Tuple[bool, List[str], float]:
        """
        Returns: (pii_found, pii_types_list, risk_score_contribution)
        """
        if not text:
            return False, [], 0.0

        found_types = []
        for pii_type, pattern in PII_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                found_types.append(pii_type)

        risk_score = min(len(found_types) * 0.15, 0.8)
        return bool(found_types), found_types, risk_score


class RiskClassifier:
    """Classifies AI agent interactions by EU AI Act risk levels."""

    @staticmethod
    def classify(prompt: str, response: str, context: dict = None) -> Dict:
        text = f"{prompt} {response}".lower()

        # Check prohibited
        for keyword in PROHIBITED_KEYWORDS:
            if keyword in text:
                return {
                    "level": "unacceptable",
                    "score": 1.0,
                    "reason": f"Prohibited use case detected: '{keyword}'",
                    "eu_ai_act_article": "Article 5",
                }

        # Check high risk
        high_risk_matches = [kw for kw in HIGH_RISK_KEYWORDS if kw in text]
        if high_risk_matches:
            return {
                "level": "high",
                "score": 0.75,
                "reason": f"High-risk use case: {', '.join(high_risk_matches[:3])}",
                "eu_ai_act_article": "Article 6 + Annex III",
            }

        # Check for limited risk (chatbots interacting with humans)
        if any(
            kw in text
            for kw in ["customer service", "chatbot", "virtual assistant", "recommend"]
        ):
            return {
                "level": "limited",
                "score": 0.35,
                "reason": "Limited risk: transparency obligations apply",
                "eu_ai_act_article": "Article 52",
            }

        return {
            "level": "minimal",
            "score": 0.1,
            "reason": "Minimal risk: standard monitoring applies",
            "eu_ai_act_article": "N/A (voluntary code of conduct)",
        }


class ComplianceFlagger:
    """Flags specific compliance violations in real-time."""

    @staticmethod
    def check(prompt: str, response: str, pii_types: List[str]) -> List[Dict]:
        flags = []

        if pii_types:
            flags.append(
                {
                    "code": "PII_EXPOSURE",
                    "severity": "high",
                    "message": f"PII detected in interaction: {', '.join(pii_types)}",
                    "regulation": "GDPR Art. 5, EU AI Act Annex IV",
                    "remediation": "Implement data minimization and pseudonymization",
                }
            )

        if len(prompt) > 10000:
            flags.append(
                {
                    "code": "LARGE_CONTEXT",
                    "severity": "medium",
                    "message": "Unusually large prompt context may indicate data exfiltration risk",
                    "regulation": "EU AI Act Annex IV §2.g",
                    "remediation": "Implement prompt size limits and content scanning",
                }
            )

        if any(
            kw in response.lower() for kw in ["as an ai", "i cannot", "i'm not able to"]
        ):
            flags.append(
                {
                    "code": "AI_DISCLOSURE",
                    "severity": "info",
                    "message": "AI system disclosed its nature to user",
                    "regulation": "EU AI Act Article 52(1)",
                    "remediation": "Log as positive transparency event",
                }
            )

        return flags


class AgentInterceptorMiddleware(BaseHTTPMiddleware):
    """
    Middleware that intercepts requests to AI proxy endpoints.
    Routes: /proxy/openai/*, /proxy/anthropic/*
    """

    PROXY_PATHS = ["/proxy/openai", "/proxy/anthropic", "/proxy/custom"]

    pii_detector = PIIDetector()
    risk_classifier = RiskClassifier()
    compliance_flagger = ComplianceFlagger()

    async def dispatch(self, request: Request, call_next):
        # Only intercept proxy paths
        if not any(request.url.path.startswith(p) for p in self.PROXY_PATHS):
            return await call_next(request)

        # Read request body
        body_bytes = await request.body()

        try:
            body = json.loads(body_bytes)
        except Exception:
            return await call_next(request)

        # Extract prompt from various formats
        prompt = self._extract_prompt(body)

        # Process the request
        response = await call_next(request)

        # Read response (note: in production use streaming-aware approach)
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk

        try:
            response_data = json.loads(response_body)
            agent_response = self._extract_response(response_data)
        except Exception:
            agent_response = ""

        # Run compliance checks asynchronously
        await self._log_interaction(
            request=request,
            body=body,
            prompt=prompt,
            response=agent_response,
            response_data=response_data if "response_data" in dir() else {},
        )

        # Return modified response
        from starlette.responses import Response as StarletteResponse

        return StarletteResponse(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

    def _extract_prompt(self, body: dict) -> str:
        """Extract prompt text from various API formats."""
        messages = body.get("messages", [])
        if messages:
            return " ".join(
                (
                    m.get("content", "")
                    if isinstance(m.get("content"), str)
                    else " ".join(
                        c.get("text", "")
                        for c in m.get("content", [])
                        if isinstance(c, dict)
                    )
                )
                for m in messages
            )
        return body.get("prompt", "")

    def _extract_response(self, response_data: dict) -> str:
        """Extract response text from various API formats."""
        choices = response_data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")

        content = response_data.get("content", [])
        if content and isinstance(content, list):
            return " ".join(c.get("text", "") for c in content if isinstance(c, dict))

        return ""

    async def _log_interaction(
        self,
        request: Request,
        body: dict,
        prompt: str,
        response: str,
        response_data: dict,
    ):
        """Log the interaction to the audit database."""
        try:
            # PII detection
            pii_found, pii_types, pii_risk = self.pii_detector.scan(
                f"{prompt} {response}"
            )

            # Risk classification
            risk_info = self.risk_classifier.classify(prompt, response)

            # Compliance flags
            flags = self.compliance_flagger.check(prompt, response, pii_types)

            # Calculate overall risk score
            risk_score = max(risk_info["score"], pii_risk)

            # Hash prompts/responses (never store raw for privacy)
            prompt_hash = (
                hashlib.sha256(prompt.encode()).hexdigest() if prompt else None
            )
            response_hash = (
                hashlib.sha256(response.encode()).hexdigest() if response else None
            )

            # Extract tool calls
            tool_calls = []
            for choice in response_data.get("choices", []):
                tc = choice.get("message", {}).get("tool_calls", [])
                tool_calls.extend(
                    [
                        {"name": t.get("function", {}).get("name"), "id": t.get("id")}
                        for t in tc
                    ]
                )

            log_entry = {
                "id": str(uuid.uuid4()),
                "agent_id": request.headers.get("X-Agent-ID", "unknown"),
                "session_id": request.headers.get("X-Session-ID"),
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "llm_call",
                "prompt_hash": prompt_hash,
                "prompt_tokens": body.get("usage", {}).get("prompt_tokens", 0),
                "response_hash": response_hash,
                "response_tokens": response_data.get("usage", {}).get(
                    "completion_tokens", 0
                ),
                "model": body.get("model", "unknown"),
                "provider": self._detect_provider(request.url.path),
                "risk_score": risk_score,
                "pii_detected": 1 if pii_found else 0,
                "pii_types": json.dumps(pii_types),
                "tool_calls": json.dumps(tool_calls),
                "compliance_flags": json.dumps(flags),
                "metadata": json.dumps(
                    {
                        "risk_level": risk_info["level"],
                        "eu_article": risk_info["eu_ai_act_article"],
                    }
                ),
                "ip_address": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            }

            async with aiosqlite.connect("agentguard.db") as db:
                await db.execute(
                    """
                    INSERT OR IGNORE INTO audit_logs 
                    (id, agent_id, session_id, timestamp, event_type, prompt_hash, prompt_tokens,
                     response_hash, response_tokens, model, provider, risk_score, pii_detected,
                     pii_types, tool_calls, compliance_flags, metadata, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    list(log_entry.values()),
                )
                await db.commit()

            if risk_score > 0.6:
                logger.warning(
                    f"HIGH RISK interaction detected: score={risk_score:.2f}, flags={len(flags)}"
                )

        except Exception as e:
            logger.error(f"Failed to log interaction: {e}", exc_info=True)

    def _detect_provider(self, path: str) -> str:
        if "openai" in path:
            return "openai"
        if "anthropic" in path:
            return "anthropic"
        if "groq" in path:
            return "groq"
        return "unknown"
