import json
from datetime import datetime, timedelta, timezone

import pytest

from validation_service.audit import GENESIS_HASH, AuditEntry, AuditLog, format_timestamp, parse_timestamp

T0 = datetime(2024, 6, 15, 12, 0, 0, 123000, tzinfo=timezone.utc)


class Clock:
    def __init__(self, start=T0, step=timedelta(minutes=1)):
        self.now = start
        self.step = step

    def __call__(self):
        current = self.now
        self.now = self.now + self.step
        return current


def _log_with_entries():
    clock = Clock()
    log = AuditLog(clock=clock)
    log.success("validator", "RECORD_VALIDATED", "TXN-1", reference="TXN-1")
    log.failure("validator", "RECORD_VALIDATED", "TXN-2", reason="bad amount")
    log.warning("reviewer", "MANUAL_REVIEW", "TXN-2", note="check")
    return log, clock


# --- timestamps ------------------------------------------------------------


def test_format_timestamp_aware_converted_to_utc():
    moment = datetime(2024, 6, 15, 14, 0, 0, 5000, tzinfo=timezone(timedelta(hours=2)))
    assert format_timestamp(moment) == "2024-06-15T12:00:00.005Z"


def test_format_timestamp_naive_assumed_utc():
    assert format_timestamp(datetime(2024, 6, 15, 12, 0, 0, 999999)) == "2024-06-15T12:00:00.999Z"


def test_format_timestamp_none_uses_now():
    before = datetime.now(timezone.utc)
    stamp = format_timestamp()
    parsed = parse_timestamp(stamp)
    assert abs((parsed - before).total_seconds()) < 5


def test_parse_timestamp_roundtrip():
    assert parse_timestamp("2024-06-15T12:00:00.123Z") == T0


def test_parse_timestamp_requires_z_suffix():
    with pytest.raises(ValueError, match="Z suffix"):
        parse_timestamp("2024-06-15T12:00:00.123+00:00")


# --- AuditEntry ------------------------------------------------------------


def test_entry_canonical_excludes_hash_and_is_deterministic():
    entry = AuditEntry(1, "2024-06-15T12:00:00.123Z", "a", "b", "c", "SUCCESS", {"k": 1}, GENESIS_HASH, "deadbeef")
    payload = json.loads(entry.canonical())
    assert "hash" not in payload
    assert payload["previous_hash"] == GENESIS_HASH
    assert entry.compute_hash() == entry.compute_hash()
    assert len(entry.compute_hash()) == 64
    assert entry.to_dict()["hash"] == "deadbeef"


# --- record ----------------------------------------------------------------


def test_records_success_entry_and_chain_verifies():
    log = AuditLog()

    entry = log.success("validator", "RECORD_VALIDATED", "TXN-1", reference="TXN-1")

    assert entry.sequence == 1
    assert entry.outcome == "SUCCESS"
    assert log.verify_chain() is True


def test_record_requires_actor_and_action():
    log = AuditLog(clock=Clock())
    with pytest.raises(ValueError, match="actor"):
        log.record("", "ACTION", "S", "SUCCESS")
    with pytest.raises(ValueError, match="action"):
        log.record("actor", "", "S", "SUCCESS")


def test_record_rejects_unknown_outcome():
    with pytest.raises(ValueError, match="unknown outcome 'MAYBE'"):
        AuditLog(clock=Clock()).record("actor", "ACTION", "S", "MAYBE")


def test_record_masks_pii_in_details_and_defaults_subject():
    log = AuditLog(clock=Clock())
    entry = log.record("actor", "ACTION", "", "SUCCESS", {"ssn": "123456789", "memo": "mail jane.doe@x.com", "n": 1})
    assert entry.subject == "-"
    assert entry.details == {"ssn": "***-**-6789", "memo": "mail ja******@x.com", "n": 1}


def test_record_none_details_becomes_empty_dict():
    entry = AuditLog(clock=Clock()).record("actor", "ACTION", "S", "SUCCESS", None)
    assert entry.details == {}


def test_record_uses_clock_and_chains_hashes():
    log, _ = _log_with_entries()
    e1, e2, e3 = log.entries
    assert [e.timestamp for e in (e1, e2, e3)] == [
        "2024-06-15T12:00:00.123Z",
        "2024-06-15T12:01:00.123Z",
        "2024-06-15T12:02:00.123Z",
    ]
    assert [e.sequence for e in (e1, e2, e3)] == [1, 2, 3]
    assert e1.previous_hash == GENESIS_HASH
    assert e2.previous_hash == e1.hash
    assert e3.previous_hash == e2.hash
    assert e3.hash == e3.compute_hash()
    assert len(log) == 3
    assert isinstance(log.entries, tuple)


def test_success_failure_warning_set_outcome():
    log, _ = _log_with_entries()
    assert [e.outcome for e in log.entries] == ["SUCCESS", "FAILURE", "WARNING"]
    assert log.entries[1].details == {"reason": "bad amount"}


# --- verify_chain ----------------------------------------------------------


def test_verify_chain_empty_log():
    assert AuditLog().verify_chain() is True


def test_verify_chain_detects_tampered_details():
    log, _ = _log_with_entries()
    original = log._entries[1]
    log._entries[1] = AuditEntry(**{**original.__dict__, "details": {"reason": "tampered"}})
    assert log.verify_chain() is False


def test_verify_chain_detects_broken_link():
    log, _ = _log_with_entries()
    original = log._entries[2]
    log._entries[2] = AuditEntry(**{**original.__dict__, "previous_hash": "f" * 64})
    assert log.verify_chain() is False


def test_verify_chain_detects_bad_sequence():
    log, _ = _log_with_entries()
    original = log._entries[1]
    log._entries[1] = AuditEntry(**{**original.__dict__, "sequence": 7})
    assert log.verify_chain() is False


# --- queries ---------------------------------------------------------------


def test_for_subject_for_actor_failures():
    log, _ = _log_with_entries()
    assert [e.sequence for e in log.for_subject("TXN-2")] == [2, 3]
    assert [e.sequence for e in log.for_actor("reviewer")] == [3]
    assert [e.sequence for e in log.failures()] == [2]
    assert log.for_subject("nope") == []


def test_between_is_exclusive_on_both_ends():
    log, _ = _log_with_entries()
    start = T0
    end = T0 + timedelta(minutes=2)
    assert [e.sequence for e in log.between(start, end)] == [2]
    assert [e.sequence for e in log.between(T0 - timedelta(seconds=1), end + timedelta(seconds=1))] == [1, 2, 3]


def test_between_end_before_start_raises():
    log, _ = _log_with_entries()
    with pytest.raises(ValueError, match="end precedes start"):
        log.between(T0, T0 - timedelta(seconds=1))


def test_counts_by_action():
    log, _ = _log_with_entries()
    assert log.counts_by_action() == {"RECORD_VALIDATED": 2, "MANUAL_REVIEW": 1}
    assert AuditLog().counts_by_action() == {}


# --- export / import -------------------------------------------------------


def test_export_ndjson():
    log, _ = _log_with_entries()
    lines = log.export_ndjson().split("\n")
    assert len(lines) == 3
    first = json.loads(lines[0])
    assert first == log.entries[0].to_dict()
    assert list(first) == sorted(first)
    assert AuditLog().export_ndjson() == ""


def test_export_csv():
    log, _ = _log_with_entries()
    rows = log.export_csv().split("\n")
    assert rows[0] == "sequence,timestamp,actor,action,subject,outcome,hash"
    assert len(rows) == 4
    e1 = log.entries[0]
    assert rows[1] == f"1,{e1.timestamp},validator,RECORD_VALIDATED,TXN-1,SUCCESS,{e1.hash}"


def test_from_entries_roundtrip():
    log, _ = _log_with_entries()
    raw = [json.loads(line) for line in log.export_ndjson().split("\n")]
    restored = AuditLog.from_entries(raw)
    assert len(restored) == 3
    assert restored.entries == log.entries
    assert restored.verify_chain() is True


def test_from_entries_chain_failure_raises():
    log, _ = _log_with_entries()
    raw = [e.to_dict() for e in log.entries]
    raw[0]["actor"] = "intruder"
    with pytest.raises(ValueError, match="chain verification"):
        AuditLog.from_entries(raw)


def test_from_entries_empty():
    assert len(AuditLog.from_entries([])) == 0


# --- retention -------------------------------------------------------------


def test_is_past_retention_with_explicit_now():
    log, _ = _log_with_entries()
    entry = log.entries[0]
    assert log.is_past_retention(entry, now=T0.replace(year=T0.year + 7)) is False
    assert log.is_past_retention(entry, now=T0.replace(year=T0.year + 8)) is True


def test_is_past_retention_uses_clock_by_default():
    clock = Clock()
    log = AuditLog(clock=clock)
    entry = log.success("a", "b", "c")
    assert log.is_past_retention(entry) is False
    clock.now = T0.replace(year=T0.year + 10)
    assert log.is_past_retention(entry) is True
