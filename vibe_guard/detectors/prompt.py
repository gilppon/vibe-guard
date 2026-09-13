"""Sub-millisecond fast-fail prompt injection and jailbreak detector."""

from __future__ import annotations

import re
from typing import NamedTuple

from vibe_guard.core import EvaluationResult, SecurityViolation
from vibe_guard.detectors.normalizer import extract_decoded_payloads, normalize_text


class PromptPattern(NamedTuple):
    code: str
    pattern: re.Pattern[str]
    risk_score: int
    reason: str


# Pre-compiled high-speed deterministic regexes (< 0.2ms execution)
_PROMPT_PATTERNS: tuple[PromptPattern, ...] = (
    PromptPattern(
        code="INSTRUCTION_OVERRIDE",
        pattern=re.compile(
            r"(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
            r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
            r"override\s+system\s+(?:instructions|prompt)|"
            r"bypass\s+all\s+(?:safety|guardrails|filters)|"
            r"system\s+override\s+mode)\b"
        ),
        risk_score=85,
        reason="System instruction override attempt detected",
    ),
    PromptPattern(
        code="SYSTEM_PROMPT_EXTRACTION",
        pattern=re.compile(
            r"(?i)\b(?:reveal|show|print|output|display|repeat)\s+(?:me\s+)?(?:your|the)\s+"
            r"(?:system\s+prompt|hidden\s+instructions|initial\s+prompt|core\s+directive)|"
            r"what\s+(?:are|is)\s+your\s+(?:exact\s+)?(?:system\s+prompt|hidden\s+instructions)\b"
        ),
        risk_score=90,
        reason="System prompt exfiltration attempt detected",
    ),
    PromptPattern(
        code="ROLE_OVERRIDE_JAILBREAK",
        pattern=re.compile(
            r"(?i)\b(?:you\s+are\s+now\s+(?:in\s+)?DAN\s+mode|"
            r"act\s+as\s+(?:an?\s+)?unfiltered|pretend\s+you\s+have\s+no\s+(?:rules|filters|morals)|"
            r"jailbreak\s+mode\s+enabled)\b"
        ),
        risk_score=80,
        reason="Role override or DAN-style jailbreak attempt detected",
    ),
    PromptPattern(
        code="DATA_EXFILTRATION_ATTEMPT",
        pattern=re.compile(
            r"(?i)\b(?:exfiltrate|send|upload)\s+(?:all\s+)?(?:secrets|credentials|api[_-]?keys|"
            r"environment\s+variables|\.env)\s+(?:to|towards)\b"
        ),
        risk_score=95,
        reason="Malicious credential exfiltration instruction detected",
    ),
)


def scan_prompt(raw_prompt: str) -> EvaluationResult:
    """Evaluate input prompt for injection, override, and jailbreak attacks in < 1ms."""
    if not raw_prompt or not raw_prompt.strip():
        return EvaluationResult(is_safe=True, cleaned_text="")

    # 1. Normalize and strip invisible homoglyphs & zero-width characters
    cleaned = normalize_text(raw_prompt)

    # 2. Check normalized prompt with pre-compiled patterns
    for rule in _PROMPT_PATTERNS:
        if rule.pattern.search(cleaned):
            return EvaluationResult(
                is_safe=False,
                violation_type=SecurityViolation.PROMPT_INJECTION,
                reason=rule.reason,
                risk_score=rule.risk_score,
                cleaned_text=cleaned,
            )

    # 3. Check any obfuscated base64/hex strings inside prompt
    decoded_candidates = extract_decoded_payloads(cleaned)
    for candidate in decoded_candidates:
        candidate_norm = normalize_text(candidate)
        for rule in _PROMPT_PATTERNS:
            if rule.pattern.search(candidate_norm):
                return EvaluationResult(
                    is_safe=False,
                    violation_type=SecurityViolation.PROMPT_INJECTION,
                    reason=f"Obfuscated injection: {rule.reason}",
                    risk_score=rule.risk_score,
                    cleaned_text=cleaned,
                )

    return EvaluationResult(
        is_safe=True,
        risk_score=0,
        cleaned_text=cleaned,
    )
