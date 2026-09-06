import pytest

from validation_service.masking import (
    card_brand,
    contains_pii,
    luhn_valid,
    mask_account_number,
    mask_card_number,
    mask_date_of_birth,
    mask_email,
    mask_name,
    mask_phone,
    mask_record,
    mask_ssn,
    mask_value_for_key,
    redact_text,
)


# --- ssn / card / account --------------------------------------------------


def test_masks_all_but_last_four_of_ssn():
    assert mask_ssn("123-45-6789") == "***-**-6789"


def test_mask_ssn_empty_and_passthrough():
    assert mask_ssn(None) == ""
    assert mask_ssn("") == ""
    assert mask_ssn("12345") == "12345"


def test_mask_ssn_unformatted_digits():
    assert mask_ssn("123456789") == "***-**-6789"


def test_masks_sixteen_digit_card_number():
    assert mask_card_number("4111 1111 1111 1111") == "************1111"


def test_mask_card_number_empty():
    assert mask_card_number(None) == ""
    assert mask_card_number("") == ""


def test_mask_card_number_too_short_raises():
    with pytest.raises(ValueError, match="too short"):
        mask_card_number("4111 1111 111")


def test_mask_account_number():
    assert mask_account_number(None) == ""
    assert mask_account_number("123456789012") == "********9012"
    assert mask_account_number("123456789012", visible=2) == "**********12"


def test_mask_account_number_visible_zero_returns_full_value():
    assert mask_account_number("123456789012", visible=0) == "************123456789012"


def test_mask_account_number_short_passthrough():
    assert mask_account_number("1234") == "1234"
    assert mask_account_number("12") == "12"


def test_mask_account_number_negative_visible_raises():
    with pytest.raises(ValueError, match="negative"):
        mask_account_number("123456", visible=-1)


# --- email / phone / name / dob --------------------------------------------


def test_mask_email_variants():
    assert mask_email(None) == ""
    assert mask_email("") == ""
    assert mask_email("no-at-sign") == "no-at-sign"
    assert mask_email("a@x.com") == "*@x.com"
    assert mask_email("abc@x.com") == "a**@x.com"
    assert mask_email("jane.doe@x.com") == "ja******@x.com"


def test_mask_phone_variants():
    assert mask_phone(None) == ""
    assert mask_phone("") == ""
    assert mask_phone("12-3") == "****"
    assert mask_phone("(415) 555-1234") == "(***) ***-1234"


def test_mask_name():
    assert mask_name(None) == ""
    assert mask_name("") == ""
    assert mask_name("Jane Q Doe") == "J*** Q D**"


def test_mask_date_of_birth():
    assert mask_date_of_birth(None) == ""
    assert mask_date_of_birth("") == ""
    assert mask_date_of_birth("1990-05-17") == "**/**/1990"
    assert mask_date_of_birth("05/17/90") == "********"


# --- key dispatch ----------------------------------------------------------


def test_mask_value_for_key_none():
    assert mask_value_for_key("ssn", None) is None


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("SSN", "123456789", "***-**-6789"),
        ("social_security_number", "123-45-6789", "***-**-6789"),
        ("tax_id", "123-45-6789", "***-**-6789"),
        ("card_number", "4111111111111111", "************1111"),
        ("pan", "4111 1111 1111 1111", "************1111"),
        ("cvv", "123", "***"),
        ("password", "hunter2", "*******"),
        ("pin", 1234, "****"),
        ("account_number", "123456789012", "********9012"),
        ("routing_number", "011000015", "*****0015"),
        ("date_of_birth", "1990-05-17", "**/**/1990"),
        ("dob", "1990-05-17", "**/**/1990"),
        ("email", "jane.doe@x.com", "ja******@x.com"),
        ("phone", "4155551234", "(***) ***-1234"),
        ("phone_number", "4155551234", "(***) ***-1234"),
        ("name", "Jane", "Jane"),
        ("amount", 12.5, 12.5),
    ],
)
def test_mask_value_for_key_branches(key, value, expected):
    assert mask_value_for_key(key, value) == expected


# --- records ---------------------------------------------------------------


def test_mask_record_nested_and_lists():
    record = {
        "ssn": "123456789",
        "Email": "jane.doe@x.com",
        "memo": "call 415 about 123-45-6789 or jane@x.com",
        "amount": 10,
        "customer": {"dob": "1990-01-01", "name": "Jane Doe"},
        "cards": [{"card_number": "4111111111111111"}, "plain", 3],
        "tags": ["a", "b"],
        "internal_id": "abc",
    }
    out = mask_record(record, extra_keys={"internal_id"})
    assert out == {
        "ssn": "***-**-6789",
        "Email": "ja******@x.com",
        "memo": "call 415 about ***-**-6789 or ja**@x.com",
        "amount": 10,
        "customer": {"dob": "**/**/1990", "name": "Jane Doe"},
        "cards": [{"card_number": "************1111"}, "plain", 3],
        "tags": ["a", "b"],
        "internal_id": "abc",
    }
    assert record["ssn"] == "123456789"


def test_mask_record_extra_key_uses_key_dispatch():
    assert mask_record({"secret": "x"}, extra_keys={"secret"}) == {"secret": "x"}


# --- redaction / detection -------------------------------------------------


def test_redact_text_empty():
    assert redact_text("") == ""
    assert redact_text(None) is None


def test_redact_text_replaces_ssn_card_and_email():
    text = "ssn 123-45-6789 card 4111-1111-1111-1111 mail jane.doe@example.com end"
    assert redact_text(text) == "ssn ***-**-6789 card ************1111 mail ja******@example.com end"


def test_contains_pii():
    assert contains_pii("") is False
    assert contains_pii(None) is False
    assert contains_pii("nothing here") is False
    assert contains_pii("ssn 123-45-6789") is True
    assert contains_pii("card 4111 1111 1111 1111") is True
    assert contains_pii("mail a@b.co") is True


# --- luhn / brand ----------------------------------------------------------


def test_luhn_valid():
    assert luhn_valid("4111 1111 1111 1111") is True
    assert luhn_valid("5500 0000 0000 0004") is True
    assert luhn_valid("3782 822463 10005") is True


def test_luhn_invalid_and_short():
    assert luhn_valid(None) is False
    assert luhn_valid("") is False
    assert luhn_valid("4111 1111 1111 1112") is False
    assert luhn_valid("4111 1111 111") is False


@pytest.mark.parametrize(
    "card,expected",
    [
        (None, "UNKNOWN"),
        ("", "UNKNOWN"),
        ("4111111111111111", "VISA"),
        ("5500000000000004", "MASTERCARD"),
        ("2221000000000009", "MASTERCARD"),
        ("2720999999999996", "MASTERCARD"),
        ("378282246310005", "AMEX"),
        ("341111111111111", "AMEX"),
        ("6011111111111117", "DISCOVER"),
        ("6500000000000002", "DISCOVER"),
        ("9999999999999999", "UNKNOWN"),
        ("12", "UNKNOWN"),
    ],
)
def test_card_brand(card, expected):
    assert card_brand(card) == expected
