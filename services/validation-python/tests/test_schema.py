from validation_service.formatters import format_currency
from validation_service.sanitizers import sanitize_free_text
from validation_service.schema import transaction_schema


def test_valid_transaction_record_passes_schema():
    result = transaction_schema().validate(
        {
            "reference": "TXN-000123",
            "account_number": "123456789012",
            "amount": "250.00",
            "currency": "USD",
            "channel": "ONLINE",
        }
    )
    assert result.is_valid is True


def test_formats_currency_and_sanitizes_text():
    assert format_currency("1234.5") == "$1,234.50"
    assert sanitize_free_text("  hello   world ") == "hello world"
