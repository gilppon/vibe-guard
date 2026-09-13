"""Core data models and exception types for vibe-guard."""

from __future__ import annotations

from enum import StrEnum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class SecurityViolation(StrEnum):
    """Enumeration of security violation categories."""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    SECRET_LEAK = "SECRET_LEAK"
    PII_LEAK = "PII_LEAK"


class EvaluationResult(BaseModel):
    """Result of an in-process security evaluation."""
    model_config = ConfigDict(frozen=True)

    is_safe: bool = Field(description="True if request is clean and safe to execute.")
    violation_type: Optional[SecurityViolation] = Field(default=None, description="Type of violation detected.")
    reason: Optional[str] = Field(default=None, description="Human-readable decision explanation.")
    risk_score: int = Field(default=0, ge=0, le=100, description="Risk severity score from 0 to 100.")
    cleaned_text: str = Field(default="", description="Sanitized and normalized text.")


class SecurityException(Exception):
    """Raised when an operation violates security policies."""

    def __init__(self, result: EvaluationResult, message: Optional[str] = None) -> None:
        self.result = result
        self.violation_type = result.violation_type
        self.risk_score = result.risk_score
        self.reason = result.reason or "Security policy violation"

        default_msg = (
            f"[VIBE-GUARD BLOCKED] {self.violation_type.value if self.violation_type else 'VIOLATION'}: "
            f"{self.reason} (risk_score={self.risk_score})"
        )
        super().__init__(message or default_msg)
