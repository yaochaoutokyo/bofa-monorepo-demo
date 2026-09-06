"""Field-level validators for customer and transaction data."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")
SSN_RE = re.compile(r"^\d{3}-?\d{2}-?\d{4}$")
ZIP_RE = re.compile(r"^\d{5}(-\d{4})?$")
ACCOUNT_RE = re.compile(r"^\d{8,17}$")
STATE_CODES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS",
    "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY",
    "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV",
    "WI", "WY", "DC", "PR", "VI", "GU",
}
SUPPORTED_CURRENCIES = {"USD", "EUR", "GBP", "JPY", "CAD"}
CHANNELS = {"ONLINE", "BRANCH", "ATM", "WIRE"}
MAX_TRANSACTION_AMOUNT = Decimal("1000000.00")


def is_valid_email(value: str | None) -> bool:
    if value is None:
        return False
    value = value.strip()
    if len(value) > 254:
        return False
    return bool(EMAIL_RE.match(value))


def is_valid_ssn(value: str | None) -> bool:
    if value is None:
        return False
    return bool(SSN_RE.match(value.strip()))


def is_valid_zip(value: str | None) -> bool:
    if not value:
        return False
    return bool(ZIP_RE.match(value.strip()))


def is_valid_state(value: str | None) -> bool:
    if not value:
        return False
    return value.strip().upper() in STATE_CODES


def is_valid_account_number(value: str | None) -> bool:
    if value is None:
        return True
    digits = value.replace(" ", "").replace("-", "")
    if digits == "":
        return True
    return bool(ACCOUNT_RE.match(digits))


def is_valid_routing_number(value: str | None) -> bool:
    """ABA routing number: 9 digits with a mod-10 weighted checksum."""
    if not value:
        return False
    digits = value.strip()
    if not digits.isdigit() or len(digits) != 9:
        return False
    weights = (7, 3, 1, 7, 3, 1, 7, 3, 1)
    total = sum(int(d) * w for d, w in zip(digits, weights))
    return total % 10 == 0


def parse_amount(value: str | int | float | Decimal | None) -> Decimal:
    if value is None:
        raise ValueError("amount is required")
    if isinstance(value, float):
        value = repr(value)
    try:
        amount = Decimal(str(value).replace(",", "").replace("$", "").strip())
    except InvalidOperation as exc:
        raise ValueError(f"amount is not numeric: {value!r}") from exc
    if amount.as_tuple().exponent < -2:
        raise ValueError("amount has more than two decimal places")
    return amount


def is_valid_transaction_amount(value: str | int | float | Decimal | None) -> bool:
    try:
        amount = parse_amount(value)
    except ValueError:
        return False
    if amount <= 0:
        return False
    return amount < MAX_TRANSACTION_AMOUNT


@dataclass
class ValidationResult:
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def add(self, field_name: str, message: str) -> None:
        self.errors[field_name] = message


def validate_transaction(record: dict) -> ValidationResult:
    """Validate a transaction record, collecting one error per failing field."""
    result = ValidationResult()
    reference = record.get("reference")
    if not reference:
        result.add("reference", "required")
    elif not re.match(r"^TXN-\d{6}$", str(reference)):
        result.add("reference", "must match TXN-NNNNNN")

    account = record.get("account_number")
    if not is_valid_account_number(account):
        result.add("account_number", "must be 8-17 digits")

    if not is_valid_transaction_amount(record.get("amount")):
        result.add("amount", "must be a positive amount below the transaction limit")

    currency = record.get("currency")
    if not currency or str(currency).upper() not in SUPPORTED_CURRENCIES:
        result.add("currency", "unsupported currency")

    channel = record.get("channel")
    if channel not in CHANNELS:
        result.add("channel", "unknown channel")

    routing = record.get("routing_number")
    if channel == "WIRE" and not is_valid_routing_number(routing):
        result.add("routing_number", "wire transfers require a valid routing number")

    return result
