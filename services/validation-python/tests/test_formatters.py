from datetime import date, datetime
from decimal import Decimal

import pytest

from validation_service.formatters import (
    format_account_number,
    format_address,
    format_boolean,
    format_cents,
    format_currency,
    format_date_iso,
    format_date_us,
    format_name,
    format_percentage,
    format_phone,
    format_record_for_export,
    format_routing_number,
    format_ssn,
    pad_reference,
    to_cents,
)


def test_format_currency_usd_default():
    assert format_currency("1234.5") == "$1,234.50"
    assert format_currency(Decimal("0.005")) == "$0.00"
    assert format_currency(Decimal("0.015")) == "$0.02"


def test_format_currency_zero_decimal_jpy():
    assert format_currency(1234.5, "jpy") == "\u00a51,234"
    assert format_currency(1235.5, "JPY") == "\u00a51,236"


def test_format_currency_negative_sign_precedes_symbol():
    assert format_currency(-42, "EUR") == "-\u20ac42.00"
    assert format_currency(-1000, "JPY") == "-\u00a51,000"


def test_format_currency_unknown_code_uses_code_prefix():
    assert format_currency("10", "sek") == "SEK 10.00"


def test_format_currency_known_symbols():
    assert format_currency(1, "GBP") == "\u00a31.00"
    assert format_currency(1, "CAD") == "CA$1.00"
    assert format_currency(1, "CHF") == "CHF 1.00"
    assert format_currency(1, "AUD") == "A$1.00"


def test_format_cents():
    assert format_cents(123456) == "$1,234.56"
    assert format_cents(-5) == "-$0.05"


def test_format_cents_jpy_uses_unit_divisor():
    assert format_cents(1234, "JPY") == "\u00a51,234"


def test_format_cents_non_int_raises():
    with pytest.raises(TypeError, match="integer"):
        format_cents(12.34)
    with pytest.raises(TypeError):
        format_cents("1234")


def test_to_cents():
    assert to_cents("12.34") == 1234
    assert to_cents(Decimal("0.005")) == 1
    assert to_cents(1.005) == 101
    assert to_cents("-1.50") == -150


def test_format_percentage():
    assert format_percentage(Decimal("0.1234")) == "12.34%"
    assert format_percentage(0.5, 0) == "50%"
    assert format_percentage(Decimal("0.12345"), 3) == "12.345%"
    assert format_percentage(Decimal("0.12345"), 2) == "12.34%"


def test_format_percentage_negative_places_raises():
    with pytest.raises(ValueError, match="negative"):
        format_percentage(0.5, -1)


def test_format_ssn():
    assert format_ssn("123 45 6789") == "123-45-6789"


def test_format_ssn_wrong_length_raises():
    with pytest.raises(ValueError, match="nine digits"):
        format_ssn("12345")


def test_format_phone():
    assert format_phone("4155551234") == "(415) 555-1234"
    assert format_phone("+1 415-555-1234") == "(415) 555-1234"


def test_format_phone_wrong_length_raises():
    with pytest.raises(ValueError, match="ten digits"):
        format_phone("555-1234")
    with pytest.raises(ValueError):
        format_phone("2-415-555-1234")


def test_format_account_number():
    assert format_account_number("1234567890") == "1234 5678 90"
    assert format_account_number("12-34-56", group=3) == "123 456"
    assert format_account_number("") == ""


def test_format_account_number_non_positive_group_raises():
    with pytest.raises(ValueError, match="positive"):
        format_account_number("1234", group=0)
    with pytest.raises(ValueError):
        format_account_number("1234", group=-2)


def test_format_date_iso_and_us():
    d = date(2021, 3, 4)
    dt = datetime(2021, 3, 4, 15, 30)
    assert format_date_iso(d) == "2021-03-04"
    assert format_date_iso(dt) == "2021-03-04"
    assert format_date_us(d) == "03/04/2021"
    assert format_date_us(dt) == "03/04/2021"


def test_format_name():
    assert format_name(" jane ", " doe ") == "Jane Doe"
    assert format_name("jane", "doe", "quinn") == "Jane Q. Doe"
    assert format_name("jane", "doe", "   ") == "Jane Doe"
    assert format_name("jane", "doe", None) == "Jane Doe"


def test_format_address():
    assert format_address(" 1 Main St ", " Springfield ", "il", " 62701 ") == "1 Main St\nSpringfield, IL 62701"
    assert format_address("1 Main St", "Springfield", "IL", "62701", line2=" Apt 4 ") == "1 Main St\nApt 4\nSpringfield, IL 62701"
    assert format_address("1 Main St", "Springfield", "IL", "62701", line2="  ") == "1 Main St\nSpringfield, IL 62701"


def test_format_routing_number():
    assert format_routing_number("011000015") == "0110-0001-5"
    assert format_routing_number("0110 0001 5") == "0110-0001-5"


def test_format_routing_number_wrong_length_raises():
    with pytest.raises(ValueError, match="nine digits"):
        format_routing_number("12345")


def test_pad_reference():
    assert pad_reference("TXN1") == "00000000TXN1"
    assert pad_reference("ab", 4, "-") == "--ab"
    assert pad_reference("abcd", 4) == "abcd"


def test_pad_reference_multi_char_fill_raises():
    with pytest.raises(ValueError, match="single character"):
        pad_reference("x", 4, "00")
    with pytest.raises(ValueError):
        pad_reference("x", 4, "")


def test_pad_reference_over_width_raises():
    with pytest.raises(ValueError, match="exceeds width"):
        pad_reference("abcde", 4)


def test_format_boolean():
    assert format_boolean(True) == "Y"
    assert format_boolean(False) == "N"


def test_format_record_for_export():
    record = {
        "amount": Decimal("12.5"),
        "when": date(2021, 3, 4),
        "at": datetime(2021, 3, 4, 5, 6),
        "flag": True,
        "off": False,
        "nothing": None,
        "count": 3,
        "text": "hi",
    }
    assert format_record_for_export(record) == {
        "amount": "12.50",
        "when": "2021-03-04",
        "at": "2021-03-04",
        "flag": "Y",
        "off": "N",
        "nothing": "",
        "count": 3,
        "text": "hi",
    }
