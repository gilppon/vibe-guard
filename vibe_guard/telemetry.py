"""Lightweight telemetry, ANSI console logging, and webhook alerts for vibe-guard."""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Optional
import urllib.request
import urllib.error

from vibe_guard.core import EvaluationResult

logger = logging.getLogger("vibe_guard")

# ANSI color codes for zero-dependency terminal styling
_COLOR_RED = "\033[91m"
_COLOR_YELLOW = "\033[93m"
_COLOR_CYAN = "\033[96m"
_COLOR_RESET = "\033[0m"


def log_block(result: EvaluationResult, context_name: str = "Agent") -> None:
    """Print high-visibility colored security alert to stdout."""
    v_type = result.violation_type.value if result.violation_type else "VIOLATION"
    print(
        f"{_COLOR_RED}[VIBE-GUARD BLOCKED]{_COLOR_RESET} "
        f"{_COLOR_YELLOW}[{v_type}]{_COLOR_RESET} "
        f"{result.reason} "
        f"{_COLOR_CYAN}(target={context_name}, risk={result.risk_score}){_COLOR_RESET}"
    )


def dispatch_webhook_alert(
    webhook_url: str,
    result: EvaluationResult,
    context: Optional[dict[str, Any]] = None,
) -> None:
    """Fire-and-forget background alert payload to a Slack webhook or HTTP endpoint."""
    if not webhook_url:
        return

    payload = {
        "text": f"🚨 [VIBE-GUARD ALERT] {result.violation_type.value if result.violation_type else 'VIOLATION'}: {result.reason}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "violation_type": result.violation_type.value if result.violation_type else "UNKNOWN",
        "risk_score": result.risk_score,
        "reason": result.reason,
        "context": context or {},
    }

    def _worker() -> None:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "vibe-guard/0.1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                _ = resp.read()
        except Exception as exc:
            logger.debug("Failed to dispatch vibe-guard webhook: %s", exc)

    # Fire-and-forget daemon thread
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
