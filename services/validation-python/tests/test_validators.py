from datetime import date, datetime
from decimal import Decimal

import pytest

from validation_service import validators as v
from validation_service.validators import (
    MAX_TRANSACTION_AMOUNT,
    age_on,
    is_valid_account_number,
    is_valid_amount,
    is_valid_currency,
    is_valid_date_of_birth,
    is_valid_email,
    is_valid_iban,
    is_valid_name,
    is_valid_phone,
    is_valid_routing_number,
    is_valid_ssn,
    is_valid_state,
    is_valid_swift,
    is_valid_tax_id,
    is_valid_zip,
    is_within_range,
    parse_amount,
    parse_date,
)


# --- email -----------------------------------------------------------------


def test_accepts_well_formed_email():
    assert is_valid_email("jane.doe@example.com") is True


def test_email_none_is_invalid():
    assert is_valid_email(None) is False


def test_email_longer_than_254_chars_is_invalid():
    assert is_valid_email("a" * 250 + "@b.co") is False


def test_email_strips_surrounding_whitespace():
    assert is_valid_email("  jane@example.com  ") is True


@pytest.mark.parametrize("value", ["", "jane", "jane@", "@example.com", "ja ne@example.com"])
def test_email_rejects_malformed(value):
    assert is_valid_email(value) is False


# --- ssn -------------------------------------------------------------------


@pytest.mark.parametrize("value", ["123-45-6789", "123456789", " 123-45-6789 ", "12345-6789"])
def test_ssn_valid(value):
    assert is_valid_ssn(value) is True


@pytest.mark.parametrize("value", [None, "", "12-345-6789", "1234567890", "abc-de-fghi"])
def test_ssn_invalid(value):
    assert is_valid_ssn(value) is False


# --- phone -----------------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["(415) 555-1234", "415-555-1234", "415.555.1234", "4155551234", "+1 415 555 1234", "1-415-555-1234"]
)
def test_phone_valid(value):
    assert is_valid_phone(value) is True


@pytest.mark.parametrize("value", [None, "", "555-1234", "41555512345", "abc"])
def test_phone_invalid(value):
    assert is_valid_phone(value) is False


# --- zip / state -----------------------------------------------------------


def test_accepts_known_state_and_zip():
    assert is_valid_state("ca") is True
    assert is_valid_zip("94105") is True


def test_zip_plus_four_valid():
    assert is_valid_zip("94105-1234") is True


@pytest.mark.parametrize("value", [None, "", "9410", "941051234", "94105-12", "ABCDE"])
def test_zip_invalid(value):
    assert is_valid_zip(value) is False


@pytest.mark.parametrize("value", [None, "", "XX", "California", "C"])
def test_state_invalid(value):
    assert is_valid_state(value) is False


def test_state_strips_and_uppercases():
    assert is_valid_state(" ny ") is True
    assert is_valid_state("DC") is True


# --- account number --------------------------------------------------------


def test_account_number_none_is_treated_as_valid():
    assert is_valid_account_number(None) is True


def test_account_number_empty_is_treated_as_valid():
    assert is_valid_account_number("") is True
    assert is_valid_account_number(" - ") is True


def test_account_number_valid_with_separators():
    assert is_valid_account_number("1234 5678 9012") is True
    assert is_valid_account_number("1234-5678-9012-34567") is True


@pytest.mark.parametrize("value", ["1234567", "123456789012345678", "12345678a"])
def test_account_number_invalid(value):
    assert is_valid_account_number(value) is False


# --- routing number --------------------------------------------------------


def _routing_checksum_ok(digits: str) -> bool:
    weights = (7, 3, 1, 7, 3, 1, 7, 3, 1)
    return sum(int(d) * w for d, w in zip(digits, weights)) % 10 == 0


def test_routing_number_valid_checksum():
    candidate = "011000013"
    assert _routing_checksum_ok(candidate) is True
    assert is_valid_routing_number(candidate) is True
    assert is_valid_routing_number(" 011000013 ") is True


def test_routing_number_invalid_checksum():
    candidate = "011000016"
    assert _routing_checksum_ok(candidate) is False
    assert is_valid_routing_number(candidate) is False


@pytest.mark.parametrize("value", [None, "", "01100001", "0110000155", "01100001a", "abcdefghi"])
def test_routing_number_rejects_non_digit_or_wrong_length(value):
    assert is_valid_routing_number(value) is False


# --- swift / currency ------------------------------------------------------


@pytest.mark.parametrize("value", ["BOFAUS3N", "bofaus3n", "BOFAUS3NXXX", " DEUTDEFF500 "])
def test_swift_valid(value):
    assert is_valid_swift(value) is True


@pytest.mark.parametrize("value", [None, "", "BOFAUS", "BOFAUS3NXX", "123456AB", "BOFAUS3N-XXX"])
def test_swift_invalid(value):
    assert is_valid_swift(value) is False


@pytest.mark.parametrize("value", ["USD", "usd", " eur ", "JPY", "GBP", "CAD", "CHF", "AUD"])
def test_currency_valid(value):
    assert is_valid_currency(value) is True


@pytest.mark.parametrize("value", [None, "", "XXX", "US", "BTC"])
def test_currency_invalid(value):
    assert is_valid_currency(value) is False


# --- amounts ---------------------------------------------------------------


def test_parse_amount_none_raises():
    with pytest.raises(ValueError, match="required"):
        parse_amount(None)


def test_parse_amount_non_numeric_raises():
    with pytest.raises(ValueError, match="not numeric"):
        parse_amount("abc")


def test_parse_amount_more_than_two_decimals_raises():
    with pytest.raises(ValueError, match="two decimal"):
        parse_amount("1.234")


def test_parse_amount_strips_commas_dollar_and_whitespace():
    assert parse_amount(" $1,234.5 ") == Decimal("1234.50")


def test_parse_amount_accepts_int_float_decimal():
    assert parse_amount(10) == Decimal("10.00")
    assert parse_amount(10.5) == Decimal("10.50")
    assert parse_amount(Decimal("3")) == Decimal("3.00")


def test_parse_amount_float_with_many_decimals_raises():
    with pytest.raises(ValueError):
        parse_amount(0.1 + 0.2)


def test_is_valid_amount_negative_false():
    assert is_valid_amount("-1.00") is False


def test_is_valid_amount_zero_depends_on_allow_zero():
    assert is_valid_amount("0") is False
    assert is_valid_amount("0", allow_zero=True) is True


def test_is_valid_amount_at_or_over_max_false():
    assert is_valid_amount(MAX_TRANSACTION_AMOUNT) is False
    assert is_valid_amount(MAX_TRANSACTION_AMOUNT + 1) is False
    assert is_valid_amount(MAX_TRANSACTION_AMOUNT - 1) is True


def test_is_valid_amount_unparseable_false():
    assert is_valid_amount("abc") is False
    assert is_valid_amount(None) is False


def test_is_valid_amount_happy_path():
    assert is_valid_amount("250.00") is True


# --- dates -----------------------------------------------------------------


def test_parse_date_none_raises():
    with pytest.raises(ValueError, match="required"):
        parse_date(None)


def test_parse_date_datetime_and_date_passthrough():
    assert parse_date(datetime(2020, 5, 17, 13, 0)) == date(2020, 5, 17)
    assert parse_date(date(2020, 5, 17)) == date(2020, 5, 17)


@pytest.mark.parametrize("text", ["2020-05-17", "05/17/2020", "20200517", "17-May-2020", " 2020-05-17 "])
def test_parse_date_supported_formats(text):
    assert parse_date(text) == date(2020, 5, 17)


def test_parse_date_bad_format_raises():
    with pytest.raises(ValueError, match="unrecognised"):
        parse_date("May 17, 2020")


def test_age_on_before_and_after_birthday():
    dob = date(2000, 6, 15)
    assert age_on(dob, date(2020, 6, 14)) == 19
    assert age_on(dob, date(2020, 6, 15)) == 20
    assert age_on(dob, date(2020, 12, 1)) == 20


def test_dob_valid_adult():
    assert is_valid_date_of_birth("1990-01-01", as_of=date(2020, 1, 1)) is True


def test_dob_future_invalid():
    assert is_valid_date_of_birth("2021-01-01", as_of=date(2020, 1, 1)) is False


def test_dob_too_young_boundary():
    as_of = date(2020, 6, 15)
    assert is_valid_date_of_birth(date(2002, 6, 16), as_of=as_of) is False
    assert is_valid_date_of_birth(date(2002, 6, 15), as_of=as_of) is True


def test_dob_too_old_boundary():
    as_of = date(2020, 6, 15)
    assert is_valid_date_of_birth(date(1900, 6, 15), as_of=as_of) is True
    assert is_valid_date_of_birth(date(1899, 6, 14), as_of=as_of) is False


def test_dob_unparseable_invalid():
    assert is_valid_date_of_birth("not-a-date") is False
    assert is_valid_date_of_birth(None) is False


def test_dob_defaults_to_today():
    assert is_valid_date_of_birth("1980-01-01") is True


# --- names / tax ids -------------------------------------------------------


def test_name_valid():
    assert is_valid_name("Mary-Jane O'Neil Jr.") is True


def test_name_none_invalid():
    assert is_valid_name(None) is False


def test_name_length_bounds():
    assert is_valid_name("") is False
    assert is_valid_name("   ") is False
    assert is_valid_name("a" * 100) is True
    assert is_valid_name("a" * 101) is False


def test_name_rejects_digits_and_symbols():
    assert is_valid_name("R2D2") is False
    assert is_valid_name("Jane@Doe") is False


def test_tax_id_ssn_form():
    assert is_valid_tax_id("123-45-6789") is True


def test_tax_id_ein_form():
    assert is_valid_tax_id("12-3456789") is True
    assert is_valid_tax_id(" 12-3456789 ") is True


@pytest.mark.parametrize("value", [None, "", "1-23456789", "1234-56789", "ab-cdefghi"])
def test_tax_id_invalid(value):
    assert is_valid_tax_id(value) is False


# --- iban ------------------------------------------------------------------


def test_iban_valid_mod97():
    assert is_valid_iban("GB82 WEST 1234 5698 7654 32") is True
    assert is_valid_iban("gb82west12345698765432") is True
    assert is_valid_iban("DE89370400440532013000") is True


def test_iban_bad_checksum():
    assert is_valid_iban("GB82WEST12345698765433") is False


def test_iban_wrong_length():
    assert is_valid_iban("GB82WEST12") is False
    assert is_valid_iban("GB82" + "0" * 31) is False


def test_iban_bad_pattern():
    assert is_valid_iban("G882WEST12345698765432") is False
    assert is_valid_iban("GBXXWEST12345698765432") is False
    assert is_valid_iban("GB82WEST-2345698765432") is False


def test_iban_empty_or_none():
    assert is_valid_iban(None) is False
    assert is_valid_iban("") is False


# --- ranges ----------------------------------------------------------------


def test_within_range_inclusive():
    assert is_within_range(5, 1, 10) is True
    assert is_within_range(1, 1, 10) is True
    assert is_within_range(10, 1, 10) is True
    assert is_within_range(11, 1, 10) is False
    assert is_within_range(Decimal("0.5"), 0, 1) is True


def test_within_range_min_exceeds_max_raises():
    with pytest.raises(ValueError, match="minimum exceeds maximum"):
        is_within_range(5, 10, 1)


def test_module_constants():
    assert v.MIN_CUSTOMER_AGE == 18
    assert v.MAX_CUSTOMER_AGE == 120
