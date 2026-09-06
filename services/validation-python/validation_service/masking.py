"""PII masking for logs, exports and customer service views."""

from __future__ import annotations

import re
from typing import Any

MASK_CHAR = "*"

_SSN_INLINE_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_INLINE_RE = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")


def mask_ssn(ssn: str | None) -> str:
    if not ssn:
        return ""
    digits = re.sub(r"\D", "", ssn)
    if len(digits) != 9:
        return ssn
    return f"{MASK_CHAR * 3}-{MASK_CHAR * 2}-{digits[-4:]}"


def mask_card_number(card: str | None) -> str:
    if not card:
        return ""
    digits = re.sub(r"\D", "", card)
    if len(digits) < 12:
        raise ValueError("card number too short to mask safely")
    return MASK_CHAR * (len(digits) - 4) + digits[-4:]


def mask_account_number(account: str | None, visible: int = 4) -> str:
    if not account:
        return ""
    if visible < 0:
        raise ValueError("visible digits cannot be negative")
    if len(account) <= visible:
        return account
    return MASK_CHAR * (len(account) - visible) + account[-visible:]


def mask_email(email: str | None) -> str:
    if not email or "@" not in email:
        return email or ""
    local, _, domain = email.partition("@")
    if len(local) <= 1:
        return f"{MASK_CHAR}@{domain}"
    keep = 1 if len(local) <= 3 else 2
    return f"{local[:keep]}{MASK_CHAR * (len(local) - keep)}@{domain}"


def mask_value_for_key(key: str, value: Any) -> Any:
    if value is None:
        return None
    lowered = key.lower()
    text = str(value)
    if lowered in ("ssn", "tax_id"):
        return mask_ssn(text)
    if lowered in ("card_number", "pan"):
        return mask_card_number(text)
    if lowered in ("cvv", "password", "pin"):
        return MASK_CHAR * len(text)
    if lowered in ("account_number", "routing_number"):
        return mask_account_number(text)
    if lowered == "email":
        return mask_email(text)
    return value


def redact_text(text: str) -> str:
    """Replace inline SSNs and card numbers in free text."""
    if not text:
        return text
    text = _SSN_INLINE_RE.sub(lambda m: mask_ssn(m.group(0)), text)
    return _CARD_INLINE_RE.sub(lambda m: mask_card_number(m.group(0)), text)


def mask_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *record* with sensitive fields masked (recursively)."""
    out: dict[str, Any] = {}
    for key, value in record.items():
        if isinstance(value, dict):
            out[key] = mask_record(value)
        elif isinstance(value, str):
            masked = mask_value_for_key(key, value)
            out[key] = redact_text(masked) if masked == value else masked
        else:
            out[key] = value
    return out


def luhn_valid(card: str | None) -> bool:
    if not card:
        return False
    digits = [int(c) for c in re.sub(r"\D", "", card)]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0
