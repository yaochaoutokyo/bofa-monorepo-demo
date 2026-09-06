from validation_service.audit import AuditLog


def test_records_success_entry():
    log = AuditLog()

    entry = log.success("validator", "RECORD_VALIDATED", "TXN-1")

    assert entry.sequence == 1
    assert entry.outcome == "SUCCESS"
    assert len(log) == 1
