from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from validation_service.normalizers import (
    normalize_account_number,
    normalize_amount,
    normalize_bool,
    normalize_country,
    normalize_currency,
    normalize_date,
    normalize_email,
    normalize_name,
    normalize_phone,
    normalize_record,
    normalize_reference,
    normalize_ssn,
    normalize_state,
    normalize_timestamp,
    normalize_zip,
)
from validation_service.rules import default_transaction_engine


# --- name ------------------------------------------------------------------


def test_normalizes_name_casing_and_state():
    assert normalize_name("  jANE   doe ") == "Jane Doe"
    assert normalize_state("ca") == "CA"


def test_normalize_name_none_and_empty():
    assert normalize_name(None) == ""
    assert normalize_name("") == ""


def test_normalize_name_mc_prefix():
    assert normalize_name("john mcdonald") == "John McDonald"
    assert normalize_name("MC") == "Mc"


def test_normalize_name_hyphenated_and_apostrophe():
    assert normalize_name("mary-jane o'neil") == "Mary-Jane O'Neil"
    assert normalize_name("anne-marie mcgee-smith") == "Anne-Marie McGee-Smith"


def test_normalize_name_short_apostrophe_not_split():
    assert normalize_name("d'") == "D'"


# --- email -----------------------------------------------------------------


def test_normalize_email_empty():
    assert normalize_email(None) == ""
    assert normalize_email("") == ""


def test_normalize_email_no_at_passthrough():
    assert normalize_email("  NotAnEmail ") == "notanemail"


def test_normalize_email_gmail_dot_plus_stripping():
    assert normalize_email("Jane.Doe+promo@GMAIL.com") == "janedoe@gmail.com"
    assert normalize_email("j.d@googlemail.com") == "jd@gmail.com"


def test_normalize_email_non_gmail_kept():
    assert normalize_email("Jane.Doe+x@Example.com") == "jane.doe+x@example.com"


# --- phone -----------------------------------------------------------------


def test_normalize_phone_empty():
    assert normalize_phone(None) == ""
    assert normalize_phone("") == ""


def test_normalize_phone_ten_digits_uses_default_country():
    assert normalize_phone("(415) 555-1234") == "+14155551234"
    assert normalize_phone("4155551234", default_country="44") == "+444155551234"


def test_normalize_phone_eleven_digits_leading_one():
    assert normalize_phone("1-415-555-1234") == "+14155551234"


def test_normalize_phone_international_plus():
    assert normalize_phone("+44 20 7946 0958") == "+442079460958"


def test_normalize_phone_invalid_raises():
    with pytest.raises(ValueError, match="cannot normalise"):
        normalize_phone("555-1234")
    with pytest.raises(ValueError):
        normalize_phone("2-415-555-1234")
    with pytest.raises(ValueError):
        normalize_phone("+1234567")


# --- ssn -------------------------------------------------------------------


def test_normalize_ssn():
    assert normalize_ssn("123 45 6789") == "123-45-6789"
    assert normalize_ssn(None) == ""


def test_normalize_ssn_invalid_length_raises():
    with pytest.raises(ValueError, match="nine digits"):
        normalize_ssn("12345")


# --- state / country -------------------------------------------------------


def test_normalize_state_names_and_unknown():
    assert normalize_state(None) == ""
    assert normalize_state("  New   York ") == "NY"
    assert normalize_state("Narnia") == "NARNIA"


def test_normalize_country():
    assert normalize_country(None) == "US"
    assert normalize_country("") == "US"
    assert normalize_country("gb") == "GB"
    assert normalize_country("United  States of America") == "US"
    assert normalize_country("U.S.") == "US"
    assert normalize_country("Germany") == "DE"
    assert normalize_country("France") == "FR"


# --- zip -------------------------------------------------------------------


def test_normalize_zip():
    assert normalize_zip(None) == ""
    assert normalize_zip("94105-1234") == "94105-1234"
    assert normalize_zip("941051234") == "94105-1234"
    assert normalize_zip("94105") == "94105"


def test_normalize_zip_four_digits_padded_on_right():
    assert normalize_zip("2134") == "21340"


def test_normalize_zip_invalid_raises():
    with pytest.raises(ValueError, match="invalid ZIP"):
        normalize_zip("123")
    with pytest.raises(ValueError):
        normalize_zip("1234567")


# --- amount ----------------------------------------------------------------


def test_normalize_amount_none_raises():
    with pytest.raises(ValueError, match="required"):
        normalize_amount(None)


def test_normalize_amount_numeric_types():
    assert normalize_amount(Decimal("1.5")) == Decimal("1.50")
    assert normalize_amount(10) == Decimal("10.00")
    assert normalize_amount(2.5) == Decimal("2.50")


def test_normalize_amount_string_forms():
    assert normalize_amount(" $1,234.5 ") == Decimal("1234.50")
    assert normalize_amount("(100)") == Decimal("-100.00")
    assert normalize_amount("100-") == Decimal("-100.00")
    assert normalize_amount("($100-)") == Decimal("-100.00")


def test_normalize_amount_invalid_raises():
    with pytest.raises(ValueError, match="invalid amount"):
        normalize_amount("abc")


# --- currency --------------------------------------------------------------


def test_normalize_currency():
    assert normalize_currency(None) == "USD"
    assert normalize_currency("") == "USD"
    assert normalize_currency("$") == "USD"
    assert normalize_currency("\u20ac") == "EUR"
    assert normalize_currency("\u00a3") == "GBP"
    assert normalize_currency("\u00a5") == "JPY"
    assert normalize_currency(" eur ") == "EUR"


# --- bool ------------------------------------------------------------------


@pytest.mark.parametrize("value", [True, 1, 5, -1, "y", "Yes", " TRUE ", "t", "1", "on"])
def test_normalize_bool_true(value):
    assert normalize_bool(value) is True


@pytest.mark.parametrize("value", [False, 0, "n", "No", "false", "F", "0", "OFF", "", None])
def test_normalize_bool_false(value):
    assert normalize_bool(value) is False


def test_normalize_bool_invalid_raises():
    with pytest.raises(ValueError, match="cannot interpret"):
        normalize_bool("maybe")


# --- date ------------------------------------------------------------------


def test_normalize_date_empty():
    assert normalize_date(None) is None
    assert normalize_date("") is None


def test_normalize_date_passthrough():
    assert normalize_date(datetime(2021, 3, 4, 5)) == date(2021, 3, 4)
    assert normalize_date(date(2021, 3, 4)) == date(2021, 3, 4)


@pytest.mark.parametrize("text", ["2021-03-04", "03/04/2021", "03-04-2021", "20210304", "4 Mar 2021", "March 04, 2021"])
def test_normalize_date_formats(text):
    assert normalize_date(text) == date(2021, 3, 4)


def test_normalize_date_invalid_raises():
    with pytest.raises(ValueError, match="unrecognised date"):
        normalize_date("4th of March")


# --- timestamp -------------------------------------------------------------


def test_normalize_timestamp_empty():
    assert normalize_timestamp(None) is None
    assert normalize_timestamp("") is None


def test_normalize_timestamp_datetime_inputs():
    naive = datetime(2021, 3, 4, 5, 6, 7)
    assert normalize_timestamp(naive) == naive.replace(tzinfo=timezone.utc)
    aware = datetime(2021, 3, 4, 5, 6, 7, tzinfo=timezone(timedelta(hours=2)))
    assert normalize_timestamp(aware) is aware


def test_normalize_timestamp_z_suffix():
    assert normalize_timestamp("2021-03-04T05:06:07Z") == datetime(2021, 3, 4, 5, 6, 7, tzinfo=timezone.utc)


def test_normalize_timestamp_naive_string_assumed_utc():
    assert normalize_timestamp(" 2021-03-04T05:06:07 ") == datetime(2021, 3, 4, 5, 6, 7, tzinfo=timezone.utc)


def test_normalize_timestamp_aware_string_converted_to_utc():
    out = normalize_timestamp("2021-03-04T05:06:07+02:00")
    assert out == datetime(2021, 3, 4, 3, 6, 7, tzinfo=timezone.utc)
    assert out.tzinfo == timezone.utc


# --- account / reference ---------------------------------------------------


def test_normalize_account_number():
    assert normalize_account_number(None) == ""
    assert normalize_account_number("0001234-567") == "1234567"
    assert normalize_account_number("0000") == "0"


def test_normalize_reference():
    assert normalize_reference(None) == ""
    assert normalize_reference(" txn-00 1_2#3 ") == "TXN-00123"


# --- record ----------------------------------------------------------------


def test_normalize_record_applies_all_normalizers():
    record = {
        "name": "jane doe",
        "email": "J@X.com",
        "phone": "4155551234",
        "ssn": "123456789",
        "state": "texas",
        "country": "usa",
        "zip": "94105",
        "amount": "$1",
        "currency": "$",
        "flag": "yes",
        "when": "2021-03-04",
        "at": "2021-03-04T00:00:00Z",
        "account": "0012",
        "ref": "a-b",
        "untouched": "  x ",
    }
    spec = {
        "name": "name",
        "email": "email",
        "phone": "phone",
        "ssn": "ssn",
        "state": "state",
        "country": "country",
        "zip": "zip",
        "amount": "amount",
        "currency": "currency",
        "flag": "bool",
        "when": "date",
        "at": "timestamp",
        "account": "account",
        "ref": "reference",
        "missing": "name",
    }
    out = normalize_record(record, spec)
    assert out["name"] == "Jane Doe"
    assert out["email"] == "j@x.com"
    assert out["phone"] == "+14155551234"
    assert out["ssn"] == "123-45-6789"
    assert out["state"] == "TX"
    assert out["country"] == "US"
    assert out["zip"] == "94105"
    assert out["amount"] == Decimal("1.00")
    assert out["currency"] == "USD"
    assert out["flag"] is True
    assert out["when"] == date(2021, 3, 4)
    assert out["at"] == datetime(2021, 3, 4, tzinfo=timezone.utc)
    assert out["account"] == "12"
    assert out["ref"] == "A-B"
    assert out["untouched"] == "  x "
    assert "missing" not in out
    assert record["name"] == "jane doe"


def test_normalize_record_unknown_normalizer_raises():
    with pytest.raises(ValueError, match="unknown normalizer 'bogus'"):
        normalize_record({"x": "1"}, {"x": "bogus"})


def test_default_engine_registers_expected_rules():
    engine = default_transaction_engine()
    assert "ctr_reporting" in engine.rule_names()
