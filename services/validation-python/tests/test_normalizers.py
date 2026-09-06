from validation_service.normalizers import normalize_name, normalize_state
from validation_service.rules import default_transaction_engine


def test_normalizes_name_casing_and_state():
    assert normalize_name("  jANE   doe ") == "Jane Doe"
    assert normalize_state("ca") == "CA"


def test_default_engine_registers_expected_rules():
    engine = default_transaction_engine()
    assert "ctr_reporting" in engine.rule_names()
