"""Canonical output formatting for validated data."""

from __future__ import annotations

from datetime import date, datetime
from decimal import ROUND_HALF_EVEN, ROUND_HALF_UP, Decimal

CURRENCY_SYMBOLS = {"USD": "$", "EUR": "\u20ac", "GBP": "\u00a3", "JPY": "\u00a5", "CAD": "CA$", "CHF": "CHF ", "AUD": "A$"}
ZERO_DECIMAL_CURRENCIES = {"JPY"}


def format_currency(amount: Decimal | int | float | str, currency: str = "USD") -> str:
    code = currency.upper()
    value = Decimal(str(amount))
    if code in ZERO_DECIMAL_CURRENCIES:
        quantized = value.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN)
        body = f"{abs(quantized):,}"
    else:
        quantized = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
        body = f"{abs(quantized):,.2f}"
    symbol = CURRENCY_SYMBOLS.get(code, code + " ")
    sign = "-" if quantized < 0 else ""
    return f"{sign}{symbol}{body}"


def format_cents(cents: int, currency: str = "USD") -> str:
    if not isinstance(cents, int):
        raise TypeError("cents must be an integer")
    divisor = 1 if currency.upper() in ZERO_DECIMAL_CURRENCIES else 100
    return format_currency(Decimal(cents) / divisor, currency)


def to_cents(amount: Decimal | str | float) -> int:
    value = Decimal(str(amount))
    return int((value * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def format_percentage(rate: Decimal | float, places: int = 2) -> str:
    if places < 0:
        raise ValueError("places cannot be negative")
    value = Decimal(str(rate)) * 100
    quantum = Decimal(1).scaleb(-places)
    return f"{value.quantize(quantum, rounding=ROUND_HALF_EVEN)}%"


def format_ssn(ssn: str) -> str:
    digits = "".join(ch for ch in ssn if ch.isdigit())
    if len(digits) != 9:
        raise ValueError("SSN must have nine digits")
    return f"{digits[:3]}-{digits[3:5]}-{digits[5:]}"


def format_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    if len(digits) == 11 and digits[0] == "1":
        digits = digits[1:]
    if len(digits) != 10:
        raise ValueError("phone number must have ten digits")
    return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"


def format_account_number(account: str, group: int = 4) -> str:
    digits = "".join(ch for ch in account if ch.isdigit())
    if group <= 0:
        raise ValueError("group size must be positive")
    return " ".join(digits[i : i + group] for i in range(0, len(digits), group))


def format_date_iso(value: date | datetime) -> str:
    if isinstance(value, datetime):
        value = value.date()
    return value.isoformat()


def format_date_us(value: date | datetime) -> str:
    if isinstance(value, datetime):
        value = value.date()
    return value.strftime("%m/%d/%Y")


def format_name(first: str, last: str, middle: str | None = None) -> str:
    parts = [first.strip().title()]
    if middle and middle.strip():
        parts.append(middle.strip()[0].upper() + ".")
    parts.append(last.strip().title())
    return " ".join(p for p in parts if p)


def format_address(line1: str, city: str, state: str, zip_code: str, line2: str | None = None) -> str:
    lines = [line1.strip()]
    if line2 and line2.strip():
        lines.append(line2.strip())
    lines.append(f"{city.strip()}, {state.strip().upper()} {zip_code.strip()}")
    return "\n".join(lines)


def format_routing_number(routing: str) -> str:
    digits = "".join(ch for ch in routing if ch.isdigit())
    if len(digits) != 9:
        raise ValueError("routing number must have nine digits")
    return f"{digits[:4]}-{digits[4:8]}-{digits[8]}"


def pad_reference(reference: str, width: int = 12, fill: str = "0") -> str:
    if len(fill) != 1:
        raise ValueError("fill must be a single character")
    if len(reference) > width:
        raise ValueError("reference exceeds width")
    return reference.rjust(width, fill)


def format_boolean(value: bool) -> str:
    return "Y" if value else "N"


def format_record_for_export(record: dict) -> dict:
    out = {}
    for key, value in record.items():
        if isinstance(value, Decimal):
            out[key] = str(value.quantize(Decimal("0.01")))
        elif isinstance(value, (date, datetime)):
            out[key] = format_date_iso(value)
        elif isinstance(value, bool):
            out[key] = format_boolean(value)
        elif value is None:
            out[key] = ""
        else:
            out[key] = value
    return out
