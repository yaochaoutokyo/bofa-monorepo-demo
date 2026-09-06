"""PII masking for logs, exports and customer service views."""

from __future__ import annotations

import re
from typing import Any

MASK_CHAR = "*"

SENSITIVE_KEYS = {
    "ssn", "social_security_number", "tax_id", "card_number", "pan", "cvv",
    "account_number", "routing_number", "password", "pin", "date_of_birth", "dob",
}

_SSN_INLINE_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_INLINE_RE = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")
_EMAIL_INLINE_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


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


def mask_phone(phone: str | None) -> str:
    if not phone:
        return ""
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return MASK_CHAR * len(phone)
    return f"({MASK_CHAR * 3}) {MASK_CHAR * 3}-{digits[-4:]}"


def mask_name(name: str | None) -> str:
    if not name:
        return ""
    parts = name.split()
    masked = []
    for part in parts:
        if len(part) <= 1:
            masked.append(part)
        else:
            masked.append(part[0] + MASK_CHAR * (len(part) - 1))
    return " ".join(masked)


def mask_date_of_birth(dob: str | None) -> str:
    if not dob:
        return ""
    match = re.search(r"(\d{4})", dob)
    if not match:
        return MASK_CHAR * len(dob)
    return f"{MASK_CHAR * 2}/{MASK_CHAR * 2}/{match.group(1)}"


def mask_value_for_key(key: str, value: Any) -> Any:
    if value is None:
        return None
    lowered = key.lower()
    text = str(value)
    if lowered in ("ssn", "social_security_number", "tax_id"):
        return mask_ssn(text)
    if lowered in ("card_number", "pan"):
        return mask_card_number(text)
    if lowered in ("cvv", "password", "pin"):
        return MASK_CHAR * len(text)
    if lowered in ("account_number", "routing_number"):
        return mask_account_number(text)
    if lowered in ("date_of_birth", "dob"):
        return mask_date_of_birth(text)
    if lowered == "email":
        return mask_email(text)
    if lowered in ("phone", "phone_number"):
        return mask_phone(text)
    return value


def mask_record(record: dict[str, Any], extra_keys: set[str] | None = None) -> dict[str, Any]:
    """Return a copy of *record* with sensitive fields masked (recursively)."""
    keys = SENSITIVE_KEYS | (extra_keys or set())
    out: dict[str, Any] = {}
    for key, value in record.items():
        if isinstance(value, dict):
            out[key] = mask_record(value, extra_keys)
        elif isinstance(value, list):
            out[key] = [mask_record(v, extra_keys) if isinstance(v, dict) else v for v in value]
        elif key.lower() in keys or key.lower() in ("email", "phone", "phone_number"):
            out[key] = mask_value_for_key(key, value)
        elif isinstance(value, str):
            out[key] = redact_text(value)
        else:
            out[key] = value
    return out


def redact_text(text: str) -> str:
    """Replace inline SSNs, card numbers and emails in free text."""
    if not text:
        return text
    text = _SSN_INLINE_RE.sub(lambda m: mask_ssn(m.group(0)), text)
    text = _CARD_INLINE_RE.sub(lambda m: mask_card_number(m.group(0)), text)
    text = _EMAIL_INLINE_RE.sub(lambda m: mask_email(m.group(0)), text)
    return text


def contains_pii(text: str) -> bool:
    if not text:
        return False
    return bool(_SSN_INLINE_RE.search(text) or _CARD_INLINE_RE.search(text) or _EMAIL_INLINE_RE.search(text))


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


def card_brand(card: str | None) -> str:
    if not card:
        return "UNKNOWN"
    digits = re.sub(r"\D", "", card)
    if digits.startswith("4"):
        return "VISA"
    if digits[:2] in {"51", "52", "53", "54", "55"} or 2221 <= int(digits[:4] or 0) <= 2720:
        return "MASTERCARD"
    if digits[:2] in {"34", "37"}:
        return "AMEX"
    if digits.startswith("6011") or digits.startswith("65"):
        return "DISCOVER"
    return "UNKNOWN"
