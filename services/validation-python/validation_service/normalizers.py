"""Normalise raw inbound values into canonical representations."""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation

from .sanitizers import collapse_whitespace, digits_only, normalize_unicode

_STATE_NAMES = {
    "california": "CA", "new york": "NY", "texas": "TX", "florida": "FL", "illinois": "IL",
    "north carolina": "NC", "massachusetts": "MA", "washington": "WA", "georgia": "GA", "arizona": "AZ",
    "district of columbia": "DC", "pennsylvania": "PA", "ohio": "OH", "michigan": "MI", "new jersey": "NJ",
}

_COUNTRY_ALIASES = {
    "usa": "US", "united states": "US", "united states of america": "US", "u.s.": "US", "u.s.a.": "US",
    "uk": "GB", "united kingdom": "GB", "great britain": "GB", "canada": "CA", "germany": "DE",
}

_BOOL_TRUE = {"y", "yes", "true", "t", "1", "on"}
_BOOL_FALSE = {"n", "no", "false", "f", "0", "off", ""}


def normalize_name(value: str | None) -> str:
    if value is None:
        return ""
    text = collapse_whitespace(normalize_unicode(value))
    return " ".join(_capitalize_part(p) for p in text.split(" "))


def _capitalize_part(part: str) -> str:
    if not part:
        return part
    if "-" in part:
        return "-".join(_capitalize_part(p) for p in part.split("-"))
    if "'" in part and len(part) > 2:
        head, _, tail = part.partition("'")
        return f"{head.capitalize()}'{tail.capitalize()}"
    lowered = part.lower()
    if lowered.startswith("mc") and len(part) > 2:
        return "Mc" + part[2:].capitalize()
    return part.capitalize()


def normalize_email(value: str | None) -> str:
    if not value:
        return ""
    text = normalize_unicode(value).strip().lower()
    local, sep, domain = text.partition("@")
    if not sep:
        return text
    if domain in ("gmail.com", "googlemail.com"):
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"
    return f"{local}@{domain}"


def normalize_phone(value: str | None, default_country: str = "1") -> str:
    if not value:
        return ""
    digits = digits_only(value)
    if len(digits) == 10:
        return f"+{default_country}{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    if value.strip().startswith("+") and 8 <= len(digits) <= 15:
        return f"+{digits}"
    raise ValueError(f"cannot normalise phone number {value!r}")


def normalize_ssn(value: str | None) -> str:
    if not value:
        return ""
    digits = digits_only(value)
    if len(digits) != 9:
        raise ValueError("SSN must contain nine digits")
    return f"{digits[:3]}-{digits[3:5]}-{digits[5:]}"


def normalize_state(value: str | None) -> str:
    if not value:
        return ""
    text = collapse_whitespace(value).lower()
    if len(text) == 2:
        return text.upper()
    return _STATE_NAMES.get(text, text.upper())


def normalize_country(value: str | None) -> str:
    if not value:
        return "US"
    text = collapse_whitespace(value).lower()
    if len(text) == 2:
        return text.upper()
    return _COUNTRY_ALIASES.get(text, text.upper()[:2])


def normalize_zip(value: str | None) -> str:
    if not value:
        return ""
    digits = digits_only(value)
    if len(digits) == 9:
        return f"{digits[:5]}-{digits[5:]}"
    if len(digits) == 5:
        return digits
    if len(digits) == 4:
        return digits + "0"
    raise ValueError(f"invalid ZIP code {value!r}")


def normalize_amount(value: str | int | float | Decimal | None) -> Decimal:
    if value is None:
        raise ValueError("amount is required")
    if isinstance(value, Decimal):
        return value.quantize(Decimal("0.01"))
    if isinstance(value, (int, float)):
        return Decimal(str(value)).quantize(Decimal("0.01"))
    text = value.strip().replace(",", "").replace("$", "")
    negative = False
    if text.startswith("(") and text.endswith(")"):
        negative = True
        text = text[1:-1]
    if text.endswith("-"):
        negative = True
        text = text[:-1]
    try:
        amount = Decimal(text)
    except InvalidOperation as exc:
        raise ValueError(f"invalid amount {value!r}") from exc
    if negative:
        amount = -amount
    return amount.quantize(Decimal("0.01"))


def normalize_currency(value: str | None) -> str:
    if not value:
        return "USD"
    text = value.strip().upper()
    symbols = {"$": "USD", "\u20ac": "EUR", "\u00a3": "GBP", "\u00a5": "JPY"}
    return symbols.get(text, text)


def normalize_bool(value: str | bool | int | None) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    text = (value or "").strip().lower()
    if text in _BOOL_TRUE:
        return True
    if text in _BOOL_FALSE:
        return False
    raise ValueError(f"cannot interpret {value!r} as boolean")


def normalize_date(value: str | date | datetime | None) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = value.strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m-%d-%Y", "%Y%m%d", "%d %b %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"unrecognised date {value!r}")


def normalize_timestamp(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_account_number(value: str | None) -> str:
    if not value:
        return ""
    digits = digits_only(value)
    return digits.lstrip("0") or "0"


def normalize_reference(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"[^A-Z0-9-]", "", value.strip().upper())


def normalize_record(record: dict, spec: dict[str, str]) -> dict:
    """Apply normalizers named in *spec* (field -> normalizer) to *record*."""
    normalizers = {
        "name": normalize_name,
        "email": normalize_email,
        "phone": normalize_phone,
        "ssn": normalize_ssn,
        "state": normalize_state,
        "country": normalize_country,
        "zip": normalize_zip,
        "amount": normalize_amount,
        "currency": normalize_currency,
        "bool": normalize_bool,
        "date": normalize_date,
        "timestamp": normalize_timestamp,
        "account": normalize_account_number,
        "reference": normalize_reference,
    }
    out = dict(record)
    for field_name, kind in spec.items():
        if field_name not in record:
            continue
        fn = normalizers.get(kind)
        if fn is None:
            raise ValueError(f"unknown normalizer {kind!r}")
        out[field_name] = fn(record[field_name])
    return out
