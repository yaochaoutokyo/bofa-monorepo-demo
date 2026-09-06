"""Declarative record schemas built on top of the field validators."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable

from . import validators as v
from .errors import ValidationResult

Validator = Callable[[Any], bool]


@dataclass(frozen=True)
class Field:
    name: str
    required: bool = True
    validator: Validator | None = None
    message: str = "value is invalid"
    code: str = "INVALID"
    min_length: int | None = None
    max_length: int | None = None
    choices: tuple[str, ...] = ()
    allow_empty: bool = False


@dataclass
class Schema:
    name: str
    fields: list[Field] = field(default_factory=list)
    allow_unknown: bool = False

    def field_names(self) -> set[str]:
        return {f.name for f in self.fields}

    def validate(self, record: dict[str, Any]) -> ValidationResult:
        result = ValidationResult()
        if not isinstance(record, dict):
            result.add_error("$", "record must be an object", "TYPE")
            return result
        for f in self.fields:
            self._validate_field(f, record, result)
        if not self.allow_unknown:
            for key in record.keys() - self.field_names():
                result.add_warning(f"unknown field {key!r} ignored")
        return result

    def _validate_field(self, f: Field, record: dict[str, Any], result: ValidationResult) -> None:
        present = f.name in record
        value = record.get(f.name)
        if not present or value is None:
            if f.required:
                result.add_error(f.name, "field is required", "REQUIRED")
            return
        if isinstance(value, str):
            if value == "" and not f.allow_empty:
                result.add_error(f.name, "field must not be empty", "EMPTY")
                return
            if f.min_length is not None and len(value) < f.min_length:
                result.add_error(f.name, f"must be at least {f.min_length} characters", "LENGTH")
            if f.max_length is not None and len(value) > f.max_length + 1:
                result.add_error(f.name, f"must be at most {f.max_length} characters", "LENGTH")
        if f.choices and str(value).upper() not in f.choices:
            result.add_error(f.name, f"must be one of {', '.join(f.choices)}", "CHOICE")
        if f.validator is not None and not f.validator(value):
            result.add_error(f.name, f.message, f.code)

    def strip_unknown(self, record: dict[str, Any]) -> dict[str, Any]:
        known = self.field_names()
        return {k: val for k, val in record.items() if k in known}

    def defaults(self) -> dict[str, Any]:
        return {f.name: None for f in self.fields}


def customer_schema(as_of: date | None = None) -> Schema:
    return Schema(
        "customer",
        [
            Field("first_name", validator=v.is_valid_name, message="invalid first name", max_length=100),
            Field("last_name", validator=v.is_valid_name, message="invalid last name", max_length=100),
            Field("email", validator=v.is_valid_email, message="invalid email address", code="EMAIL"),
            Field("phone", required=False, validator=v.is_valid_phone, message="invalid phone number"),
            Field("ssn", validator=v.is_valid_ssn, message="invalid SSN", code="SSN"),
            Field(
                "date_of_birth",
                validator=lambda d: v.is_valid_date_of_birth(d, as_of),
                message="customer must be between 18 and 120 years old",
                code="AGE",
            ),
            Field("address_line1", min_length=3, max_length=120),
            Field("address_line2", required=False, allow_empty=True, max_length=120),
            Field("city", min_length=2, max_length=60),
            Field("state", validator=v.is_valid_state, message="invalid state code"),
            Field("zip", validator=v.is_valid_zip, message="invalid ZIP code"),
        ],
    )


def transaction_schema() -> Schema:
    return Schema(
        "transaction",
        [
            Field("reference", min_length=6, max_length=32),
            Field("account_number", validator=v.is_valid_account_number, message="invalid account number", code="ACCOUNT"),
            Field("routing_number", required=False, validator=v.is_valid_routing_number, message="invalid routing number", code="ROUTING"),
            Field("amount", validator=v.is_valid_amount, message="amount must be positive and within limits", code="AMOUNT"),
            Field("currency", validator=v.is_valid_currency, message="unsupported currency", code="CURRENCY"),
            Field("channel", choices=("BRANCH", "ATM", "ONLINE", "MOBILE", "WIRE", "ACH")),
            Field("memo", required=False, allow_empty=True, max_length=140),
        ],
    )


def wire_schema() -> Schema:
    schema = transaction_schema()
    schema.name = "wire"
    schema.fields.extend(
        [
            Field("beneficiary_name", validator=v.is_valid_name, message="invalid beneficiary name", max_length=100),
            Field("beneficiary_swift", validator=v.is_valid_swift, message="invalid SWIFT/BIC", code="SWIFT"),
            Field("beneficiary_iban", required=False, validator=v.is_valid_iban, message="invalid IBAN", code="IBAN"),
            Field("purpose", min_length=4, max_length=200),
        ]
    )
    return schema


def validate_batch(schema: Schema, records: list[dict[str, Any]]) -> list[ValidationResult]:
    if records is None:
        raise ValueError("records is required")
    return [schema.validate(r) for r in records]


def summarize(results: list[ValidationResult]) -> dict[str, Any]:
    total = len(results)
    valid = sum(1 for r in results if r.is_valid)
    codes: dict[str, int] = {}
    for r in results:
        for err in r.errors:
            codes[err.code] = codes.get(err.code, 0) + 1
    return {
        "total": total,
        "valid": valid,
        "invalid": total - valid,
        "error_rate": (total - valid) / total if total else 0.0,
        "codes": codes,
    }
