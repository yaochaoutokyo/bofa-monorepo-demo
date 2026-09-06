from datetime import date, timedelta

import pytest

from validation_service.errors import ValidationResult
from validation_service.rules import (
    CTR_THRESHOLD,
    DAILY_ACH_LIMIT,
    DAILY_WIRE_LIMIT,
    RuleEngine,
    default_kyc_engine,
    default_transaction_engine,
    risk_score,
    risk_tier,
    rule_address_consistency,
    rule_ctr_reporting,
    rule_daily_limits,
    rule_duplicate_reference,
    rule_high_risk_country,
    rule_id_expiry,
    rule_minor_account,
    rule_pep_review,
    rule_structuring,
    rule_velocity,
)

AS_OF = date(2024, 6, 15)


def _run(rule, record):
    result = ValidationResult()
    rule(record, result)
    return result


def _err_codes(result):
    return [e.code for e in result.errors]


# --- engine ----------------------------------------------------------------


def test_register_bad_severity_raises():
    with pytest.raises(ValueError, match="severity"):
        RuleEngine().register("x", lambda r, res: None, "INFO")


def test_register_duplicate_name_raises():
    engine = RuleEngine().register("x", lambda r, res: None)
    with pytest.raises(ValueError, match="already registered"):
        engine.register("x", lambda r, res: None)


def test_register_returns_self_and_rule_names_ordered():
    engine = RuleEngine()
    assert engine.register("a", lambda r, res: None) is engine
    engine.register("b", lambda r, res: None, "WARNING")
    assert engine.rule_names() == ["a", "b"]


def test_evaluate_warning_rule_downgrades_errors_and_keeps_warnings():
    def noisy(record, result):
        result.add_error("f", "boom", "X")
        result.add_warning("careful")

    engine = RuleEngine().register("noisy", noisy, "WARNING")
    result = engine.evaluate({})
    assert result.is_valid is True
    assert result.warnings == ["noisy: boom", "careful"]


def test_evaluate_error_rule_merges_errors_and_warnings():
    def noisy(record, result):
        result.add_error("f", "boom", "X")
        result.add_warning("careful")

    engine = RuleEngine().register("noisy", noisy)
    result = engine.evaluate({})
    assert result.is_valid is False
    assert _err_codes(result) == ["X"]
    assert result.warnings == ["careful"]


def test_evaluate_empty_engine():
    assert RuleEngine().evaluate({"anything": 1}).is_valid is True


# --- ctr / structuring -----------------------------------------------------


def test_ctr_reporting_warns_for_cash_channels_at_threshold():
    for channel in ("branch", "ATM", "CASH"):
        result = _run(rule_ctr_reporting, {"amount": CTR_THRESHOLD, "channel": channel})
        assert result.warnings == ["currency transaction report required"]


def test_ctr_reporting_silent_below_threshold_or_electronic():
    assert _run(rule_ctr_reporting, {"amount": "9999.99", "channel": "BRANCH"}).warnings == []
    assert _run(rule_ctr_reporting, {"amount": "50000", "channel": "WIRE"}).warnings == []
    assert _run(rule_ctr_reporting, {"amount": "50000"}).warnings == []


def test_structuring_flags_three_near_threshold_deposits():
    result = _run(rule_structuring, {"recent_cash_amounts": ["9000", "9500", "9999.99"]})
    assert _err_codes(result) == ["AML_STRUCTURING"]
    assert result.errors[0].field_name == "amount"


def test_structuring_not_flagged_with_two_or_out_of_band_amounts():
    assert _run(rule_structuring, {"recent_cash_amounts": ["9500", "9500"]}).is_valid
    assert _run(rule_structuring, {"recent_cash_amounts": ["8999.99", "10000", "9500", "500"]}).is_valid
    assert _run(rule_structuring, {}).is_valid
    assert _run(rule_structuring, {"recent_cash_amounts": None}).is_valid


# --- daily limits ----------------------------------------------------------


def test_daily_limits_ach():
    ok = _run(rule_daily_limits, {"amount": "1000", "amount_today": DAILY_ACH_LIMIT - 1000, "channel": "ach"})
    assert ok.is_valid
    over = _run(rule_daily_limits, {"amount": "1000.01", "amount_today": DAILY_ACH_LIMIT - 1000, "channel": "ACH"})
    assert _err_codes(over) == ["LIMIT"]
    assert "ACH" in over.errors[0].message


def test_daily_limits_wire():
    ok = _run(rule_daily_limits, {"amount": DAILY_WIRE_LIMIT, "channel": "WIRE"})
    assert ok.is_valid
    over = _run(rule_daily_limits, {"amount": DAILY_WIRE_LIMIT + 1, "channel": "WIRE"})
    assert _err_codes(over) == ["LIMIT"]
    assert "wire" in over.errors[0].message


def test_daily_limits_other_channels_unlimited():
    assert _run(rule_daily_limits, {"amount": "999999", "channel": "BRANCH"}).is_valid


# --- country / pep ---------------------------------------------------------


def test_high_risk_country():
    result = _run(rule_high_risk_country, {"counterparty_country": "ir"})
    assert _err_codes(result) == ["SANCTIONS"]
    assert "IR" in result.errors[0].message
    assert _run(rule_high_risk_country, {"counterparty_country": "GB"}).is_valid
    assert _run(rule_high_risk_country, {}).is_valid


def test_pep_review():
    assert _run(rule_pep_review, {"amount": "100000"}).warnings == []
    assert _run(rule_pep_review, {"is_pep": True, "amount": "5000"}).warnings == []
    result = _run(rule_pep_review, {"is_pep": True, "amount": "5000.01"})
    assert result.warnings == ["politically exposed person transaction requires enhanced review"]


# --- kyc -------------------------------------------------------------------


def test_minor_account_missing_dob():
    result = _run(rule_minor_account, {})
    assert _err_codes(result) == ["KYC"]
    assert result.errors[0].field_name == "date_of_birth"


def test_minor_account_without_custodian_rejected():
    result = _run(rule_minor_account, {"date_of_birth": "2010-01-01", "as_of": AS_OF})
    assert _err_codes(result) == ["KYC"]
    assert result.errors[0].field_name == "custodian_id"


def test_minor_account_with_custodian_ok():
    assert _run(rule_minor_account, {"date_of_birth": "2010-01-01", "as_of": AS_OF, "custodian_id": "C1"}).is_valid


def test_adult_account_ok_with_default_as_of():
    assert _run(rule_minor_account, {"date_of_birth": "1980-01-01"}).is_valid


def test_id_expiry_missing():
    result = _run(rule_id_expiry, {})
    assert _err_codes(result) == ["KYC"]
    assert result.errors[0].field_name == "id_expiry"


def test_id_expiry_expired():
    result = _run(rule_id_expiry, {"id_expiry": AS_OF - timedelta(days=1), "as_of": AS_OF})
    assert [e.message for e in result.errors] == ["government ID has expired"]


def test_id_expiry_today_is_accepted_with_warning():
    result = _run(rule_id_expiry, {"id_expiry": AS_OF, "as_of": AS_OF})
    assert result.is_valid
    assert result.warnings == ["government ID expires within 30 days"]


def test_id_expiry_near_expiry_warns():
    result = _run(rule_id_expiry, {"id_expiry": AS_OF + timedelta(days=29), "as_of": AS_OF})
    assert result.is_valid
    assert result.warnings == ["government ID expires within 30 days"]


def test_id_expiry_far_future_clean():
    result = _run(rule_id_expiry, {"id_expiry": "2030-01-01", "as_of": AS_OF})
    assert result.is_valid and result.warnings == []


def test_id_expiry_default_as_of_today():
    assert _run(rule_id_expiry, {"id_expiry": "2999-01-01"}).is_valid


def test_address_consistency():
    assert _run(rule_address_consistency, {}).is_valid
    assert _run(rule_address_consistency, {"state": "CA"}).is_valid
    assert _run(rule_address_consistency, {"zip": "94105"}).is_valid
    assert _run(rule_address_consistency, {"state": "ca", "zip": "94105"}).is_valid
    assert _run(rule_address_consistency, {"state": "WA", "zip": "94105"}).is_valid
    assert _run(rule_address_consistency, {"state": "CA", "zip": "ABCDE"}).is_valid
    bad = _run(rule_address_consistency, {"state": "NY", "zip": "94105"})
    assert _err_codes(bad) == ["ADDRESS"]
    assert bad.errors[0].message == "ZIP code 94105 is not in state NY"


# --- velocity / duplicate --------------------------------------------------


def test_velocity_negative_raises():
    with pytest.raises(ValueError, match="negative"):
        _run(rule_velocity, {"transactions_last_hour": -1})


def test_velocity_thresholds():
    assert _run(rule_velocity, {}).to_dict() == {"valid": True, "errors": [], "warnings": []}
    assert _run(rule_velocity, {"transactions_last_hour": 9}).warnings == []
    warn = _run(rule_velocity, {"transactions_last_hour": "10"})
    assert warn.is_valid and warn.warnings == ["elevated transaction velocity"]
    err = _run(rule_velocity, {"transactions_last_hour": 20})
    assert _err_codes(err) == ["VELOCITY"] and err.warnings == []


def test_duplicate_reference():
    assert _run(rule_duplicate_reference, {}).is_valid
    assert _run(rule_duplicate_reference, {"reference": "A", "recent_references": None}).is_valid
    assert _run(rule_duplicate_reference, {"reference": "A", "recent_references": ["B"]}).is_valid
    assert _err_codes(_run(rule_duplicate_reference, {"reference": "A", "recent_references": ["A"]})) == ["DUPLICATE"]


# --- default engines -------------------------------------------------------


def test_default_transaction_engine_rules_and_evaluation():
    engine = default_transaction_engine()
    assert engine.rule_names() == [
        "ctr_reporting",
        "structuring",
        "daily_limits",
        "high_risk_country",
        "pep_review",
        "velocity",
        "duplicate_reference",
    ]
    result = engine.evaluate(
        {"amount": "12000", "channel": "ATM", "is_pep": True, "counterparty_country": "KP", "transactions_last_hour": 25}
    )
    assert set(_err_codes(result)) == {"SANCTIONS", "VELOCITY"}
    assert result.warnings == [
        "currency transaction report required",
        "politically exposed person transaction requires enhanced review",
    ]


def test_default_kyc_engine_rules():
    engine = default_kyc_engine()
    assert engine.rule_names() == ["minor_account", "id_expiry", "address_consistency"]
    result = engine.evaluate({"date_of_birth": "1980-01-01", "id_expiry": "2999-01-01", "state": "TX", "zip": "75001"})
    assert result.is_valid


# --- risk ------------------------------------------------------------------


def test_risk_score_zero_for_plain_record():
    assert risk_score({}) == 0
    assert risk_score({"amount": "100", "channel": "ONLINE", "counterparty_country": "us"}) == 0


def test_risk_score_individual_signals():
    assert risk_score({"amount": "10000"}) == 30
    assert risk_score({"amount": "9000"}) == 20
    assert risk_score({"amount": "8999.99"}) == 0
    assert risk_score({"counterparty_country": "gb"}) == 15
    assert risk_score({"is_pep": True}) == 25
    assert risk_score({"transactions_last_hour": 10}) == 15
    assert risk_score({"transactions_last_hour": 9}) == 0
    assert risk_score({"new_customer": True}) == 10
    assert risk_score({"channel": "wire"}) == 10
    assert risk_score({"channel": "CRYPTO"}) == 10


def test_risk_score_capped_at_100():
    record = {
        "amount": "20000",
        "counterparty_country": "RU",
        "is_pep": True,
        "transactions_last_hour": 50,
        "new_customer": True,
        "channel": "WIRE",
    }
    assert risk_score(record) == 100


def test_risk_tier_boundaries():
    assert risk_tier(0) == "LOW"
    assert risk_tier(39) == "LOW"
    assert risk_tier(40) == "MEDIUM"
    assert risk_tier(69) == "MEDIUM"
    assert risk_tier(70) == "HIGH"
    assert risk_tier(100) == "HIGH"


@pytest.mark.parametrize("score", [-1, 101])
def test_risk_tier_out_of_range_raises(score):
    with pytest.raises(ValueError, match="between 0 and 100"):
        risk_tier(score)
