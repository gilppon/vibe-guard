"""Text normalization and obfuscation stripping for vibe-guard."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Matches continuous base64-like blocks of length >= 24
_BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,4096}={0,2}(?![A-Za-z0-9+/=])")
# Matches hex blocks of length >= 32
_HEX_PATTERN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,4096}(?![0-9A-Fa-f])")


def normalize_text(text: str) -> str:
    """Normalize unicode, strip zero-width characters and invisible control codes."""
    if not text:
        return ""

    # Canonicalize Unicode to NFKC
    canonical = unicodedata.normalize("NFKC", text.replace("\r\n", "\n").replace("\r", "\n"))

    output: list[str] = []
    for char in canonical:
        category = unicodedata.category(char)
        # Cf: Format characters (Zero-width spaces \u200b, joiners \u200c, \u200d, BOM \ufeff)
        if category == "Cf":
            continue
        # Cc: Control characters (Preserve \n, \t)
        if category == "Cc" and char not in {"\n", "\t"}:
            continue
        output.append(char)

    return "".join(output).strip()


def extract_decoded_payloads(text: str, max_candidates: int = 8) -> list[str]:
    """Attempt to decode embedded base64 and hex strings to expose hidden instructions."""
    decoded_strings: list[str] = []

    # Check Base64
    for match in _BASE64_PATTERN.finditer(text):
        candidate = match.group(0)
        try:
            padded = candidate + ("=" * (-len(candidate) % 4))
            decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore")
            if len(decoded) >= 8 and decoded.isprintable():
                decoded_strings.append(decoded)
        except (binascii.Error, ValueError):
            pass
        if len(decoded_strings) >= max_candidates:
            break

    # Check Hex
    if len(decoded_strings) < max_candidates:
        for match in _HEX_PATTERN.finditer(text):
            candidate = match.group(0)
            if len(candidate) % 2 == 0:
                try:
                    decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
                    if len(decoded) >= 8 and decoded.isprintable():
                        decoded_strings.append(decoded)
                except (ValueError, UnicodeDecodeError):
                    pass
            if len(decoded_strings) >= max_candidates:
                break

    return decoded_strings
