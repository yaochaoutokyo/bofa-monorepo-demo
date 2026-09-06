from datetime import date

import pytest

from validation_service.errors import ValidationResult
from validation_service.formatters import format_currency
from validation_service.sanitizers import sanitize_free_text
from validation_service.schema import (
    Field,
    Schema,
    customer_schema,
    summarize,
    transaction_schema,
    validate_batch,
    wire_schema,
)

VALID_TXN = {
    "reference": "TXN-000123",
    "account_number": "123456789012",
    "amount": "250.00",
    "currency": "USD",
    "channel": "ONLINE",
}

AS_OF = date(2024, 6, 15)

VALID_CUSTOMER = {
    "first_name": "Jane",
    "last_name": "Doe",
    "email": "jane@example.com",
    "ssn": "123-45-6789",
    "date_of_birth": "1990-01-01",
    "address_line1": "1 Main St",
    "city": "Springfield",
    "state": "IL",
    "zip": "62701",
}


def _codes(result):
    return [e.code for e in result.errors]


def test_valid_transaction_record_passes_schema():
    result = transaction_schema().validate(VALID_TXN)
    assert result.is_valid is True


def test_formats_currency_and_sanitizes_text():
    assert format_currency("1234.5") == "$1,234.50"
    assert sanitize_free_text("  hello   world ") == "hello world"


# --- Schema.validate -------------------------------------------------------


def test_validate_non_dict_record():
    result = Schema("s", [Field("x")]).validate(["not", "a", "dict"])
    assert _codes(result) == ["TYPE"]
    assert result.errors[0].field_name == "$"


def test_required_missing_and_none():
    schema = Schema("s", [Field("a"), Field("b"), Field("c", required=False)])
    result = schema.validate({"b": None})
    assert [(e.field_name, e.code) for e in result.errors] == [("a", "REQUIRED"), ("b", "REQUIRED")]


def test_empty_string_rejected_unless_allow_empty():
    strict = Schema("s", [Field("a", min_length=3)])
    result = strict.validate({"a": ""})
    assert _codes(result) == ["EMPTY"]

    lenient = Schema("s", [Field("a", allow_empty=True, min_length=3)])
    result = lenient.validate({"a": ""})
    assert _codes(result) == ["LENGTH"]
    assert "at least 3" in result.errors[0].message


def test_min_length():
    schema = Schema("s", [Field("a", min_length=3)])
    assert schema.validate({"a": "ab"}).errors[0].code == "LENGTH"
    assert schema.validate({"a": "abc"}).is_valid


def test_max_length_allows_one_extra_character():
    schema = Schema("s", [Field("a", max_length=5)])
    assert schema.validate({"a": "abcde"}).is_valid
    assert schema.validate({"a": "abcdef"}).is_valid
    result = schema.validate({"a": "abcdefg"})
    assert _codes(result) == ["LENGTH"]
    assert result.errors[0].message == "must be at most 5 characters"


def test_length_checks_skipped_for_non_strings():
    schema = Schema("s", [Field("a", min_length=3, max_length=5)])
    assert schema.validate({"a": 12}).is_valid


def test_choices_case_insensitive():
    schema = Schema("s", [Field("a", choices=("X", "Y"))])
    assert schema.validate({"a": "x"}).is_valid
    result = schema.validate({"a": "z"})
    assert _codes(result) == ["CHOICE"]
    assert result.errors[0].message == "must be one of X, Y"


def test_custom_validator_failure_uses_message_and_code():
    schema = Schema("s", [Field("a", validator=lambda v: v > 0, message="must be positive", code="POS")])
    assert schema.validate({"a": 1}).is_valid
    result = schema.validate({"a": -1})
    assert result.errors[0].to_dict() == {"field": "a", "message": "must be positive", "code": "POS"}


def test_unknown_field_warning_and_allow_unknown():
    schema = Schema("s", [Field("a")])
    result = schema.validate({"a": "x", "extra": 1})
    assert result.is_valid
    assert result.warnings == ["unknown field 'extra' ignored"]

    permissive = Schema("s", [Field("a")], allow_unknown=True)
    assert permissive.validate({"a": "x", "extra": 1}).warnings == []


def test_field_names_strip_unknown_defaults():
    schema = Schema("s", [Field("a"), Field("b", required=False)])
    assert schema.field_names() == {"a", "b"}
    assert schema.strip_unknown({"a": 1, "b": 2, "c": 3}) == {"a": 1, "b": 2}
    assert schema.defaults() == {"a": None, "b": None}


# --- built-in schemas ------------------------------------------------------


def test_customer_schema_valid():
    result = customer_schema(as_of=AS_OF).validate(VALID_CUSTOMER)
    assert result.is_valid, result.to_dict()


def test_customer_schema_optional_fields():
    record = dict(VALID_CUSTOMER, phone="415-555-1234", address_line2="")
    assert customer_schema(as_of=AS_OF).validate(record).is_valid


def test_customer_schema_rejects_bad_values():
    record = dict(
        VALID_CUSTOMER,
        first_name="J4ne",
        email="nope",
        phone="123",
        ssn="12-3",
        date_of_birth="2020-01-01",
        address_line1="ab",
        city="x",
        state="ZZ",
        zip="1",
    )
    result = customer_schema(as_of=AS_OF).validate(record)
    assert result.error_fields() == {
        "first_name",
        "email",
        "phone",
        "ssn",
        "date_of_birth",
        "address_line1",
        "city",
        "state",
        "zip",
    }
    assert "EMAIL" in _codes(result)
    assert "SSN" in _codes(result)
    assert "AGE" in _codes(result)


def test_customer_schema_default_as_of():
    assert customer_schema().validate(VALID_CUSTOMER).is_valid


def test_transaction_schema_rejects_bad_values():
    record = {
        "reference": "TXN",
        "account_number": "12",
        "routing_number": "123",
        "amount": "-1",
        "currency": "XXX",
        "channel": "CARRIER_PIGEON",
        "memo": "",
    }
    result = transaction_schema().validate(record)
    assert set(_codes(result)) == {"LENGTH", "ACCOUNT", "ROUTING", "AMOUNT", "CURRENCY", "CHOICE"}


def test_wire_schema_extends_transaction_schema():
    schema = wire_schema()
    assert schema.name == "wire"
    assert transaction_schema().field_names() < schema.field_names()
    assert {"beneficiary_name", "beneficiary_swift", "beneficiary_iban", "purpose"} <= schema.field_names()

    valid = dict(
        VALID_TXN,
        channel="WIRE",
        beneficiary_name="John Smith",
        beneficiary_swift="DEUTDEFF",
        beneficiary_iban="DE89 3704 0044 0532 0130 00",
        purpose="Invoice 42",
    )
    assert schema.validate(valid).is_valid

    invalid = dict(valid, beneficiary_swift="BAD", beneficiary_iban="DE00", purpose="x", beneficiary_name="")
    result = schema.validate(invalid)
    assert set(_codes(result)) == {"SWIFT", "IBAN", "LENGTH", "EMPTY"}


# --- batch / summary -------------------------------------------------------


def test_validate_batch_none_raises():
    with pytest.raises(ValueError, match="required"):
        validate_batch(transaction_schema(), None)


def test_validate_batch_returns_one_result_per_record():
    results = validate_batch(transaction_schema(), [VALID_TXN, {}])
    assert [r.is_valid for r in results] == [True, False]
    assert validate_batch(transaction_schema(), []) == []


def test_summarize_empty():
    assert summarize([]) == {"total": 0, "valid": 0, "invalid": 0, "error_rate": 0.0, "codes": {}}


def test_summarize_counts_codes():
    ok = ValidationResult()
    bad = ValidationResult()
    bad.add_error("a", "m", "X")
    bad.add_error("b", "m", "X")
    worse = ValidationResult()
    worse.add_error("c", "m", "Y")
    summary = summarize([ok, bad, worse])
    assert summary["total"] == 3
    assert summary["valid"] == 1
    assert summary["invalid"] == 2
    assert summary["error_rate"] == pytest.approx(2 / 3)
    assert summary["codes"] == {"X": 2, "Y": 1}
