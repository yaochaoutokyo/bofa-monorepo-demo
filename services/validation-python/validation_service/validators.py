"""Field-level validators for customer and transaction data."""

from __future__ import annotations

import re
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")
SSN_RE = re.compile(r"^\d{3}-?\d{2}-?\d{4}$")
PHONE_RE = re.compile(r"^\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$")
ZIP_RE = re.compile(r"^\d{5}(-\d{4})?$")
ACCOUNT_RE = re.compile(r"^\d{8,17}$")
SWIFT_RE = re.compile(r"^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$")
STATE_CODES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS",
    "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY",
    "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV",
    "WI", "WY", "DC", "PR", "VI", "GU",
}
SUPPORTED_CURRENCIES = {"USD", "EUR", "GBP", "JPY", "CAD", "CHF", "AUD"}

MAX_TRANSACTION_AMOUNT = Decimal("1000000.00")
MIN_CUSTOMER_AGE = 18
MAX_CUSTOMER_AGE = 120


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


def is_valid_phone(value: str | None) -> bool:
    if not value:
        return False
    return bool(PHONE_RE.match(value.strip()))


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


def is_valid_swift(value: str | None) -> bool:
    if not value:
        return False
    return bool(SWIFT_RE.match(value.strip().upper()))


def is_valid_currency(value: str | None) -> bool:
    if not value:
        return False
    return value.strip().upper() in SUPPORTED_CURRENCIES


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
    return amount.quantize(Decimal("0.01"))


def is_valid_amount(value: str | int | float | Decimal | None, allow_zero: bool = False) -> bool:
    try:
        amount = parse_amount(value)
    except ValueError:
        return False
    if amount < 0:
        return False
    if amount == 0 and not allow_zero:
        return False
    if amount >= MAX_TRANSACTION_AMOUNT:
        return False
    return True


def parse_date(value: str | date | datetime | None) -> date:
    if value is None:
        raise ValueError("date is required")
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = value.strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y%m%d", "%d-%b-%Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"unrecognised date format: {value!r}")


def age_on(birth_date: date, as_of: date) -> int:
    years = as_of.year - birth_date.year
    if (as_of.month, as_of.day) < (birth_date.month, birth_date.day):
        years -= 1
    return years


def is_valid_date_of_birth(value: str | date | None, as_of: date | None = None) -> bool:
    try:
        dob = parse_date(value)
    except ValueError:
        return False
    today = as_of or date.today()
    if dob > today:
        return False
    years = age_on(dob, today)
    return MIN_CUSTOMER_AGE <= years <= MAX_CUSTOMER_AGE


def is_valid_name(value: str | None) -> bool:
    if value is None:
        return False
    name = value.strip()
    if not 1 <= len(name) <= 100:
        return False
    return all(ch.isalpha() or ch in " '-." for ch in name)


def is_valid_tax_id(value: str | None) -> bool:
    """Accepts either an SSN or an EIN (NN-NNNNNNN)."""
    if not value:
        return False
    text = value.strip()
    if is_valid_ssn(text):
        return True
    return bool(re.match(r"^\d{2}-\d{7}$", text))


def is_valid_iban(value: str | None) -> bool:
    if not value:
        return False
    iban = value.replace(" ", "").upper()
    if not 15 <= len(iban) <= 34:
        return False
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", iban):
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def is_within_range(value: int | float | Decimal, minimum: int | float | Decimal, maximum: int | float | Decimal) -> bool:
    if minimum > maximum:
        raise ValueError("minimum exceeds maximum")
    return minimum <= value <= maximum
