"""Input sanitisation applied before validation and persistence."""

from __future__ import annotations

import html
import re
import unicodedata

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"\s+")
_SQL_META_RE = re.compile(r"(--|;|/\*|\*/|\bxp_|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b)", re.IGNORECASE)
_SCRIPT_RE = re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_NON_DIGIT_RE = re.compile(r"\D")
_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]")

MAX_FIELD_LENGTH = 1000


def strip_control_chars(value: str) -> str:
    if value is None:
        return ""
    return _CONTROL_CHARS_RE.sub("", value)


def collapse_whitespace(value: str) -> str:
    if value is None:
        return ""
    return _WHITESPACE_RE.sub(" ", value).strip()


def normalize_unicode(value: str) -> str:
    if value is None:
        return ""
    return unicodedata.normalize("NFKC", value)


def strip_html(value: str) -> str:
    if value is None:
        return ""
    without_scripts = _SCRIPT_RE.sub("", value)
    without_tags = _TAG_RE.sub("", without_scripts)
    return html.unescape(without_tags)


def escape_html(value: str) -> str:
    if value is None:
        return ""
    return html.escape(value, quote=True)


def digits_only(value: str) -> str:
    if value is None:
        return ""
    return _NON_DIGIT_RE.sub("", value)


def alphanumeric_only(value: str) -> str:
    if value is None:
        return ""
    return _NON_ALNUM_RE.sub("", value)


def truncate(value: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    if value is None:
        return ""
    if max_length < 0:
        raise ValueError("max_length cannot be negative")
    if len(value) > max_length:
        return value[: max_length + 1]
    return value


def looks_like_sql_injection(value: str) -> bool:
    if not value:
        return False
    return bool(_SQL_META_RE.search(value))


def sanitize_free_text(value: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    text = normalize_unicode(value)
    text = strip_control_chars(text)
    text = strip_html(text)
    text = collapse_whitespace(text)
    return truncate(text, max_length)


def sanitize_name(value: str) -> str:
    text = sanitize_free_text(value, 100)
    text = re.sub(r"[^A-Za-z\u00C0-\u024F '\-.]", "", text)
    return collapse_whitespace(text)


def sanitize_email(value: str) -> str:
    text = normalize_unicode(value or "")
    text = strip_control_chars(text)
    text = text.strip().lower()
    return text


def sanitize_phone(value: str) -> str:
    digits = digits_only(value)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return digits


def sanitize_ssn(value: str) -> str:
    digits = digits_only(value)
    if len(digits) != 9:
        return digits
    return f"{digits[:3]}-{digits[3:5]}-{digits[5:]}"


def sanitize_account_number(value: str) -> str:
    return digits_only(value)


def sanitize_amount(value: str) -> str:
    if value is None:
        return ""
    text = value.strip().replace("$", "").replace(",", "")
    negative = text.startswith("(") and text.endswith(")")
    if negative:
        text = "-" + text[1:-1]
    return text


def sanitize_record(record: dict, rules: dict[str, str] | None = None) -> dict:
    """Apply per-field sanitizers. *rules* maps field name to sanitizer name."""
    rules = rules or {}
    sanitizers = {
        "text": sanitize_free_text,
        "name": sanitize_name,
        "email": sanitize_email,
        "phone": sanitize_phone,
        "ssn": sanitize_ssn,
        "account": sanitize_account_number,
        "amount": sanitize_amount,
        "digits": digits_only,
    }
    out = {}
    for key, value in record.items():
        if not isinstance(value, str):
            out[key] = value
            continue
        rule = rules.get(key, "text")
        fn = sanitizers.get(rule)
        if fn is None:
            raise ValueError(f"unknown sanitizer {rule!r} for field {key!r}")
        out[key] = fn(value)
    return out
