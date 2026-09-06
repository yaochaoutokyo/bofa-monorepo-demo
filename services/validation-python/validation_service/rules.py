"""Business rules that span multiple fields (KYC, AML, limits)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal
from typing import Any, Callable

from .errors import ValidationResult
from .validators import age_on, parse_amount, parse_date

CTR_THRESHOLD = Decimal("10000.00")
STRUCTURING_FLOOR = Decimal("9000.00")
DAILY_ACH_LIMIT = Decimal("25000.00")
DAILY_WIRE_LIMIT = Decimal("250000.00")
HIGH_RISK_COUNTRIES = {"IR", "KP", "SY", "CU", "RU", "BY", "MM"}
PEP_REVIEW_THRESHOLD = Decimal("5000.00")

RuleFn = Callable[[dict[str, Any], ValidationResult], None]


@dataclass(frozen=True)
class Rule:
    name: str
    fn: RuleFn
    severity: str = "ERROR"


class RuleEngine:
    def __init__(self):
        self._rules: list[Rule] = []

    def register(self, name: str, fn: RuleFn, severity: str = "ERROR") -> "RuleEngine":
        if severity not in ("ERROR", "WARNING"):
            raise ValueError("severity must be ERROR or WARNING")
        if any(r.name == name for r in self._rules):
            raise ValueError(f"rule {name!r} already registered")
        self._rules.append(Rule(name, fn, severity))
        return self

    def evaluate(self, record: dict[str, Any]) -> ValidationResult:
        result = ValidationResult()
        for rule in self._rules:
            partial = ValidationResult()
            rule.fn(record, partial)
            if rule.severity == "WARNING":
                for err in partial.errors:
                    result.add_warning(f"{rule.name}: {err.message}")
                result.warnings.extend(partial.warnings)
            else:
                result.merge(partial)
        return result

    def rule_names(self) -> list[str]:
        return [r.name for r in self._rules]


def rule_ctr_reporting(record: dict[str, Any], result: ValidationResult) -> None:
    amount = parse_amount(record.get("amount"))
    channel = str(record.get("channel", "")).upper()
    if amount >= CTR_THRESHOLD and channel in ("BRANCH", "ATM", "CASH"):
        result.add_warning("currency transaction report required")


def rule_structuring(record: dict[str, Any], result: ValidationResult) -> None:
    history = record.get("recent_cash_amounts") or []
    amounts = [parse_amount(a) for a in history]
    near = [a for a in amounts if STRUCTURING_FLOOR <= a < CTR_THRESHOLD]
    if len(near) >= 3 and sum(near) >= CTR_THRESHOLD:
        result.add_error("amount", "pattern consistent with structuring", "AML_STRUCTURING")


def rule_daily_limits(record: dict[str, Any], result: ValidationResult) -> None:
    amount = parse_amount(record.get("amount"))
    prior = parse_amount(record.get("amount_today", "0"))
    channel = str(record.get("channel", "")).upper()
    total = amount + prior
    if channel == "ACH" and total > DAILY_ACH_LIMIT:
        result.add_error("amount", f"daily ACH limit of {DAILY_ACH_LIMIT} exceeded", "LIMIT")
    if channel == "WIRE" and total > DAILY_WIRE_LIMIT:
        result.add_error("amount", f"daily wire limit of {DAILY_WIRE_LIMIT} exceeded", "LIMIT")


def rule_high_risk_country(record: dict[str, Any], result: ValidationResult) -> None:
    country = str(record.get("counterparty_country", "US")).upper()
    if country in HIGH_RISK_COUNTRIES:
        result.add_error("counterparty_country", f"transactions with {country} are blocked", "SANCTIONS")


def rule_pep_review(record: dict[str, Any], result: ValidationResult) -> None:
    if not record.get("is_pep"):
        return
    amount = parse_amount(record.get("amount"))
    if amount > PEP_REVIEW_THRESHOLD:
        result.add_warning("politically exposed person transaction requires enhanced review")


def rule_minor_account(record: dict[str, Any], result: ValidationResult) -> None:
    dob = record.get("date_of_birth")
    if not dob:
        result.add_error("date_of_birth", "date of birth is required for KYC", "KYC")
        return
    years = age_on(parse_date(dob), record.get("as_of") or date.today())
    if years < 18 and not record.get("custodian_id"):
        result.add_error("custodian_id", "minor accounts require a custodian", "KYC")


def rule_id_expiry(record: dict[str, Any], result: ValidationResult) -> None:
    expiry = record.get("id_expiry")
    if not expiry:
        result.add_error("id_expiry", "government ID expiry is required", "KYC")
        return
    exp = parse_date(expiry)
    today = record.get("as_of") or date.today()
    if exp < today:
        result.add_error("id_expiry", "government ID has expired", "KYC")
    elif exp - today < timedelta(days=30):
        result.add_warning("government ID expires within 30 days")


def rule_address_consistency(record: dict[str, Any], result: ValidationResult) -> None:
    state = str(record.get("state", "")).upper()
    zip_code = str(record.get("zip", ""))
    if not state or not zip_code:
        return
    prefix = zip_code[:3]
    ranges = {"CA": range(900, 962), "NY": range(100, 150), "TX": range(750, 800), "FL": range(320, 350)}
    if state in ranges and prefix.isdigit() and int(prefix) not in ranges[state]:
        result.add_error("zip", f"ZIP code {zip_code} is not in state {state}", "ADDRESS")


def rule_velocity(record: dict[str, Any], result: ValidationResult) -> None:
    count = int(record.get("transactions_last_hour", 0))
    if count < 0:
        raise ValueError("transaction count cannot be negative")
    if count >= 20:
        result.add_error("velocity", "too many transactions in the last hour", "VELOCITY")
    elif count >= 10:
        result.add_warning("elevated transaction velocity")


def rule_duplicate_reference(record: dict[str, Any], result: ValidationResult) -> None:
    ref = record.get("reference")
    seen = record.get("recent_references") or []
    if ref and ref in seen:
        result.add_error("reference", "duplicate transaction reference", "DUPLICATE")


def default_transaction_engine() -> RuleEngine:
    engine = RuleEngine()
    engine.register("ctr_reporting", rule_ctr_reporting, "WARNING")
    engine.register("structuring", rule_structuring)
    engine.register("daily_limits", rule_daily_limits)
    engine.register("high_risk_country", rule_high_risk_country)
    engine.register("pep_review", rule_pep_review, "WARNING")
    engine.register("velocity", rule_velocity)
    engine.register("duplicate_reference", rule_duplicate_reference)
    return engine


def default_kyc_engine() -> RuleEngine:
    engine = RuleEngine()
    engine.register("minor_account", rule_minor_account)
    engine.register("id_expiry", rule_id_expiry)
    engine.register("address_consistency", rule_address_consistency)
    return engine


def risk_score(record: dict[str, Any]) -> int:
    """Return a 0-100 risk score from a handful of weighted signals."""
    score = 0
    amount = parse_amount(record.get("amount", "0"))
    if amount >= CTR_THRESHOLD:
        score += 30
    elif amount >= STRUCTURING_FLOOR:
        score += 20
    if str(record.get("counterparty_country", "US")).upper() != "US":
        score += 15
    if record.get("is_pep"):
        score += 25
    if int(record.get("transactions_last_hour", 0)) >= 10:
        score += 15
    if record.get("new_customer"):
        score += 10
    if str(record.get("channel", "")).upper() in ("WIRE", "CRYPTO"):
        score += 10
    return min(score, 100)


def risk_tier(score: int) -> str:
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
