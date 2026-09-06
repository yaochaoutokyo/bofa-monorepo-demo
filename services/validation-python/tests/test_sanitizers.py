import pytest

from validation_service.sanitizers import (
    MAX_FIELD_LENGTH,
    alphanumeric_only,
    collapse_whitespace,
    digits_only,
    escape_html,
    looks_like_sql_injection,
    normalize_unicode,
    sanitize_account_number,
    sanitize_amount,
    sanitize_email,
    sanitize_free_text,
    sanitize_name,
    sanitize_phone,
    sanitize_record,
    sanitize_ssn,
    strip_control_chars,
    strip_html,
    truncate,
)


def test_strip_control_chars_removes_controls_but_keeps_whitespace():
    assert strip_control_chars("a\x00b\x07c\td\ne\x7f") == "abc\td\ne"


def test_strip_control_chars_none():
    assert strip_control_chars(None) == ""


def test_collapse_whitespace():
    assert collapse_whitespace("  a \t\n b   c ") == "a b c"
    assert collapse_whitespace(None) == ""


def test_normalize_unicode_nfkc():
    assert normalize_unicode("\ufb01") == "fi"
    assert normalize_unicode("\u2460") == "1"
    assert normalize_unicode(None) == ""


def test_strip_html_removes_scripts_tags_and_unescapes():
    raw = "<p>Hello <b>world</b></p><script>alert('x')</script> &amp; &lt;ok&gt;"
    assert strip_html(raw) == "Hello world & <ok>"


def test_strip_html_multiline_script():
    raw = "before< SCRIPT type='x'>\nbad()\n< / script >after"
    assert strip_html(raw) == "beforeafter"


def test_strip_html_none():
    assert strip_html(None) == ""


def test_escape_html():
    assert escape_html("<a href=\"x\">'&'</a>") == "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
    assert escape_html(None) == ""


def test_digits_only():
    assert digits_only("(415) 555-1234 ext. 9") == "41555512349"
    assert digits_only(None) == ""


def test_alphanumeric_only():
    assert alphanumeric_only("A-1 b_2!c3") == "A1b2c3"
    assert alphanumeric_only(None) == ""


def test_truncate_none():
    assert truncate(None) == ""


def test_truncate_negative_raises():
    with pytest.raises(ValueError, match="negative"):
        truncate("abc", -1)


def test_truncate_short_value_unchanged():
    assert truncate("abc", 5) == "abc"
    assert truncate("abcde", 5) == "abcde"


def test_truncate_keeps_max_length_plus_one_chars():
    assert truncate("abcdefgh", 5) == "abcdef"
    assert len(truncate("x" * (MAX_FIELD_LENGTH + 50))) == MAX_FIELD_LENGTH + 1


@pytest.mark.parametrize(
    "value",
    ["1; DROP TABLE users", "x' -- comment", "a UNION select b", "/* hi */", "exec xp_cmdshell", "insert into t", "delete from t"],
)
def test_looks_like_sql_injection_positive(value):
    assert looks_like_sql_injection(value) is True


@pytest.mark.parametrize("value", ["", None, "hello world", "selected items", "dropping by"])
def test_looks_like_sql_injection_negative(value):
    assert looks_like_sql_injection(value) is False


def test_sanitize_free_text_pipeline():
    raw = "  <b>Hel\x00lo</b>\u00a0 \n world\ufb01 "
    assert sanitize_free_text(raw) == "Hello worldfi"


def test_sanitize_free_text_respects_max_length():
    assert sanitize_free_text("abcdefghij", 3) == "abcd"


def test_sanitize_name_strips_disallowed_characters():
    assert sanitize_name("  Jos\u00e9   O'Neil-Smith Jr.3 <x> ") == "Jos\u00e9 O'Neil-Smith Jr."


def test_sanitize_name_collapses_after_removal():
    assert sanitize_name("Jane 123 Doe") == "Jane Doe"


def test_sanitize_email():
    assert sanitize_email("  Jane.DOE@Example.COM\x00 ") == "jane.doe@example.com"
    assert sanitize_email(None) == ""
    assert sanitize_email("") == ""


def test_sanitize_phone_strips_leading_country_code():
    assert sanitize_phone("+1 (415) 555-1234") == "4155551234"
    assert sanitize_phone("415-555-1234") == "4155551234"
    assert sanitize_phone("+44 20 7946 0958") == "442079460958"
    assert sanitize_phone("2-415-555-1234") == "24155551234"


def test_sanitize_ssn_formats_nine_digits():
    assert sanitize_ssn("123 45 6789") == "123-45-6789"
    assert sanitize_ssn("123456789") == "123-45-6789"


def test_sanitize_ssn_passthrough_when_not_nine_digits():
    assert sanitize_ssn("12345") == "12345"
    assert sanitize_ssn("") == ""


def test_sanitize_account_number():
    assert sanitize_account_number("1234-5678 90ab") == "1234567890"


def test_sanitize_amount_none():
    assert sanitize_amount(None) == ""


def test_sanitize_amount_strips_symbols():
    assert sanitize_amount(" $1,234.56 ") == "1234.56"


def test_sanitize_amount_parenthesized_negative():
    assert sanitize_amount("($1,000.00)") == "-1000.00"
    assert sanitize_amount("(100") == "(100"


def test_sanitize_record_default_rule_is_text():
    out = sanitize_record({"memo": "  <i>hi</i>  there "})
    assert out == {"memo": "hi there"}


def test_sanitize_record_dispatches_by_rule_and_passes_non_strings():
    record = {
        "name": "jane <b>doe</b> 9",
        "email": " J@X.COM ",
        "phone": "+1 415 555 1234",
        "ssn": "123456789",
        "account": "12-34",
        "amount": "($5)",
        "digits": "a1b2",
        "count": 3,
        "flag": None,
    }
    rules = {
        "name": "name",
        "email": "email",
        "phone": "phone",
        "ssn": "ssn",
        "account": "account",
        "amount": "amount",
        "digits": "digits",
    }
    assert sanitize_record(record, rules) == {
        "name": "jane doe",
        "email": "j@x.com",
        "phone": "4155551234",
        "ssn": "123-45-6789",
        "account": "1234",
        "amount": "-5",
        "digits": "12",
        "count": 3,
        "flag": None,
    }


def test_sanitize_record_unknown_sanitizer_raises():
    with pytest.raises(ValueError, match="unknown sanitizer 'bogus' for field 'x'"):
        sanitize_record({"x": "y"}, {"x": "bogus"})
