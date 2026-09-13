"""API key, Secret, and PII detector & redactor for vibe-guard."""

from __future__ import annotations

import re
from typing import NamedTuple

from vibe_guard.core import EvaluationResult, SecurityViolation


class RedactPattern(NamedTuple):
    label: str
    pattern: re.Pattern[str]
    replacement: str
    is_secret: bool


_REDACT_PATTERNS: tuple[RedactPattern, ...] = (
    # AWS Access Keys
    RedactPattern(
        label="AWS_KEY",
        pattern=re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        replacement="[REDACTED_AWS_KEY]",
        is_secret=True,
    ),
    # OpenAI / Anthropic / Generic API Keys
    RedactPattern(
        label="API_KEY",
        pattern=re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,255})\b"),
        replacement="[REDACTED_API_KEY]",
        is_secret=True,
    ),
    # JWT Tokens
    RedactPattern(
        label="JWT_TOKEN",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        replacement="[REDACTED_JWT]",
        is_secret=True,
    ),
    # Credit Card Numbers
    RedactPattern(
        label="CREDIT_CARD",
        pattern=re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
        replacement="[REDACTED_CREDIT_CARD]",
        is_secret=False,
    ),
    # Email Addresses
    RedactPattern(
        label="EMAIL_ADDRESS",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        replacement="[REDACTED_EMAIL]",
        is_secret=False,
    ),
)


def mask_pii_and_secrets(raw_text: str) -> tuple[str, list[str]]:
    """Scan and deterministically redact sensitive API keys and PII."""
    if not raw_text:
        return "", []

    sanitized = raw_text
    detected_labels: list[str] = []

    for rule in _REDACT_PATTERNS:
        if rule.pattern.search(sanitized):
            detected_labels.append(rule.label)
            sanitized = rule.pattern.sub(rule.replacement, sanitized)

    return sanitized, detected_labels


def scan_output(output_text: str, mask: bool = True) -> EvaluationResult:
    """Evaluate LLM or tool output for secrets and PII leaks."""
    if not output_text or not output_text.strip():
        return EvaluationResult(is_safe=True, cleaned_text="")

    sanitized, detected = mask_pii_and_secrets(output_text)

    if detected:
        has_secret = any(label in {"AWS_KEY", "API_KEY", "JWT_TOKEN"} for label in detected)
        violation = SecurityViolation.SECRET_LEAK if has_secret else SecurityViolation.PII_LEAK
        return EvaluationResult(
            is_safe=False,
            violation_type=violation,
            reason=f"Sensitive items detected: {', '.join(detected)}",
            risk_score=85 if has_secret else 60,
            cleaned_text=sanitized if mask else output_text,
        )

    return EvaluationResult(is_safe=True, risk_score=0, cleaned_text=output_text)
