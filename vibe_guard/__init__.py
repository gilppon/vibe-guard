"""vibe-guard: Ultra-lightweight, zero-config AI agent security SDK."""

from vibe_guard.core import EvaluationResult, SecurityException, SecurityViolation
from vibe_guard.detectors import (
    check_path,
    check_url,
    mask_pii_and_secrets,
    normalize_text,
    scan_output,
    scan_prompt,
)
from vibe_guard.guard import SafeAgent, SafeTool, protect, safe_tool

__version__ = "0.1.0"

__all__ = [
    "protect",
    "SafeAgent",
    "SafeTool",
    "safe_tool",
    "SecurityException",
    "EvaluationResult",
    "SecurityViolation",
    "scan_prompt",
    "scan_output",
    "check_path",
    "check_url",
    "normalize_text",
    "mask_pii_and_secrets",
]
