import pytest

from validation_service.errors import ValidationError, ValidationResult


def test_validation_error_message_and_to_dict():
    err = ValidationError("amount", "must be positive", "AMOUNT")
    assert str(err) == "amount: must be positive"
    assert err.field_name == "amount"
    assert err.message == "must be positive"
    assert err.code == "AMOUNT"
    assert err.to_dict() == {"field": "amount", "message": "must be positive", "code": "AMOUNT"}


def test_validation_error_default_code():
    assert ValidationError("f", "m").code == "INVALID"


def test_empty_result_is_valid():
    result = ValidationResult()
    assert result.is_valid is True
    assert result.errors == []
    assert result.warnings == []


def test_add_error_marks_invalid():
    result = ValidationResult()
    result.add_error("email", "bad email", "EMAIL")
    result.add_error("ssn", "bad ssn")
    assert result.is_valid is False
    assert [e.code for e in result.errors] == ["EMAIL", "INVALID"]


def test_add_warning_does_not_affect_validity():
    result = ValidationResult()
    result.add_warning("heads up")
    assert result.is_valid is True
    assert result.warnings == ["heads up"]


def test_merge_combines_and_returns_self():
    a = ValidationResult()
    a.add_error("x", "bad x")
    a.add_warning("wa")
    b = ValidationResult()
    b.add_error("y", "bad y")
    b.add_warning("wb")

    merged = a.merge(b)

    assert merged is a
    assert [e.field_name for e in a.errors] == ["x", "y"]
    assert a.warnings == ["wa", "wb"]


def test_error_fields_is_set_of_unique_fields():
    result = ValidationResult()
    result.add_error("x", "one")
    result.add_error("x", "two")
    result.add_error("y", "three")
    assert result.error_fields() == {"x", "y"}


def test_to_dict():
    result = ValidationResult()
    result.add_error("x", "bad", "CODE")
    result.add_warning("w")
    assert result.to_dict() == {
        "valid": False,
        "errors": [{"field": "x", "message": "bad", "code": "CODE"}],
        "warnings": ["w"],
    }


def test_raise_if_invalid_raises_first_error():
    result = ValidationResult()
    result.add_error("first", "one")
    result.add_error("second", "two")
    with pytest.raises(ValidationError) as excinfo:
        result.raise_if_invalid()
    assert excinfo.value.field_name == "first"


def test_raise_if_invalid_noop_when_valid():
    result = ValidationResult()
    result.add_warning("only a warning")
    result.raise_if_invalid()
