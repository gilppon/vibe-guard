"""Path Traversal and SSRF resource firewall for vibe-guard."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from vibe_guard.core import EvaluationResult, SecurityViolation

# Known sensitive filesystem indicators
_SENSITIVE_FILES = {"passwd", "shadow", "id_rsa", "id_ed25519", "credentials", ".env"}
_SENSITIVE_DIRS = {".ssh", ".aws", ".gnupg", ".kube", "system32"}
_SENSITIVE_EXTS = {".pem", ".key", ".pfx", ".p12"}

# Cloud metadata destinations
_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    "100.100.100.200",  # Alibaba Cloud metadata
}


def check_path(raw_path: str) -> EvaluationResult:
    """Validate file path against path traversal and sensitive directory access."""
    if not raw_path or not str(raw_path).strip():
        return EvaluationResult(is_safe=True, cleaned_text="")

    path_str = str(raw_path).replace("\\", "/")

    # 1. Obvious Traversal Sequence Check
    if "../" in path_str or "..\\" in str(raw_path) or "%2e%2e" in path_str.lower():
        return EvaluationResult(
            is_safe=False,
            violation_type=SecurityViolation.PATH_TRAVERSAL,
            reason="Directory traversal sequence ('../') detected in path",
            risk_score=95,
            cleaned_text=path_str,
        )

    # 2. Sensitive Path & File Checks
    parts = {p.lower() for p in Path(path_str).parts}
    filename = Path(path_str).name.lower()
    suffix = Path(path_str).suffix.lower()

    if parts & _SENSITIVE_DIRS:
        return EvaluationResult(
            is_safe=False,
            violation_type=SecurityViolation.PATH_TRAVERSAL,
            reason=f"Access to sensitive directory blocked: {parts & _SENSITIVE_DIRS}",
            risk_score=90,
            cleaned_text=path_str,
        )

    if filename in _SENSITIVE_FILES or filename.startswith(".env") or suffix in _SENSITIVE_EXTS:
        return EvaluationResult(
            is_safe=False,
            violation_type=SecurityViolation.PATH_TRAVERSAL,
            reason=f"Access to sensitive credential file blocked: {filename}",
            risk_score=90,
            cleaned_text=path_str,
        )

    return EvaluationResult(is_safe=True, risk_score=0, cleaned_text=path_str)


def check_url(raw_url: str) -> EvaluationResult:
    """Validate destination URL against SSRF, cloud metadata, and private network IPs."""
    if not raw_url or not str(raw_url).strip():
        return EvaluationResult(is_safe=True, cleaned_text="")

    url_str = str(raw_url).strip()
    try:
        parsed = urlparse(url_str)
        hostname = (parsed.hostname or parsed.path.split("/")[0] or "").lower()
    except Exception as exc:
        return EvaluationResult(
            is_safe=False,
            violation_type=SecurityViolation.SSRF,
            reason=f"Malformed URL structure: {exc}",
            risk_score=75,
            cleaned_text=url_str,
        )

    # 1. Cloud Metadata Block
    if hostname in _CLOUD_METADATA_HOSTS:
        return EvaluationResult(
            is_safe=False,
            violation_type=SecurityViolation.SSRF,
            reason=f"SSRF attempt against cloud metadata endpoint: {hostname}",
            risk_score=100,
            cleaned_text=url_str,
        )

    # 2. Localhost Names
    if hostname in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return EvaluationResult(
            is_safe=False,
            violation_type=SecurityViolation.SSRF,
            reason=f"SSRF attempt against loopback/localhost: {hostname}",
            risk_score=90,
            cleaned_text=url_str,
        )

    # 3. IP Address Parsing & Private Network Verification
    try:
        ip = ipaddress.ip_address(hostname)
        if not ip.is_global:
            return EvaluationResult(
                is_safe=False,
                violation_type=SecurityViolation.SSRF,
                reason=f"SSRF attempt against non-global/private network IP: {ip}",
                risk_score=95,
                cleaned_text=url_str,
            )
    except ValueError:
        # Not a raw IP (standard domain name)
        pass

    return EvaluationResult(is_safe=True, risk_score=0, cleaned_text=url_str)
