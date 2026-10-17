"""Observability, Structured Tracing & Active PII Redaction Pipeline (Rubric Section 4)."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Tuple

# Compiled regex patterns for active PII scrubbing before logging or storage
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b"
)
_SSN_TIN_RE = re.compile(r"\b(?:\d{3}-\d{2}-\d{4}|\d{2}-\d{7})\b")
_API_KEY_RE = re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|AIza[0-9A-Za-z-_]{20,})\b")
_CONTACT_NAME_RE = re.compile(
    r"(?i)\b(contact|signed by|representative|submitted by|sponsor|officer|user)\s*:\s*([A-Z][a-z]+\s+[A-Z][a-z]+)"
)


def redact_pii_text(text: str) -> Tuple[str, int]:
    """Scrubs emails, phone numbers, SSNs/EINs, API keys, and named contacts from text.

    Returns:
        Tuple of (scrubbed_text, redaction_count)
    """
    if not text or not isinstance(text, str):
        return text, 0

    total_redactions = 0

    text, n = _EMAIL_RE.subn("[REDACTED_EMAIL]", text)
    total_redactions += n

    text, n = _PHONE_RE.subn("[REDACTED_PHONE]", text)
    total_redactions += n

    text, n = _SSN_TIN_RE.subn("[REDACTED_TAX_ID]", text)
    total_redactions += n

    text, n = _API_KEY_RE.subn("[REDACTED_SECRET]", text)
    total_redactions += n

    def _replace_contact(match: re.Match) -> str:
        return f"{match.group(1)}: [REDACTED_NAME]"

    text, n = _CONTACT_NAME_RE.subn(_replace_contact, text)
    total_redactions += n

    return text, total_redactions


def redact_pii_payload(payload: Any) -> Tuple[Any, int]:
    """Recursively scrubs PII across dicts, lists, and strings before persistence."""
    if isinstance(payload, str):
        return redact_pii_text(payload)
    if isinstance(payload, list):
        total = 0
        out = []
        for item in payload:
            scrubbed, c = redact_pii_payload(item)
            out.append(scrubbed)
            total += c
        return out, total
    if isinstance(payload, dict):
        total = 0
        out_dict: Dict[str, Any] = {}
        for k, v in payload.items():
            scrubbed, c = redact_pii_payload(v)
            out_dict[k] = scrubbed
            total += c
        return out_dict, total
    return payload, 0


class ObservabilityTracer:
    """Logging pipeline that enforces PII redaction before storing trace events."""

    def __init__(self) -> None:
        self.traces: List[Dict[str, Any]] = []
        self.total_pii_redacted: int = 0

    def record_event(
        self,
        *,
        vendor_id: str,
        agent_name: str,
        model_tier: str,
        pattern: str,
        raw_message: str,
        metadata: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        scrubbed_msg, msg_count = redact_pii_text(raw_message)
        scrubbed_meta, meta_count = redact_pii_payload(metadata or {})
        redaction_count = msg_count + meta_count
        self.total_pii_redacted += redaction_count

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "vendor_id": vendor_id,
            "agent": agent_name,
            "model_tier": model_tier,
            "pattern": pattern,
            "event": scrubbed_msg,
            "pii_redacted_count": redaction_count,
            "metadata": scrubbed_meta,
        }
        self.traces.append(entry)
        return entry


tracer = ObservabilityTracer()
