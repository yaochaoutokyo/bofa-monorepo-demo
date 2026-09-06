from validation_service.audit import AuditLog


def test_records_success_entry_and_chain_verifies():
    log = AuditLog()

    entry = log.success("validator", "RECORD_VALIDATED", "TXN-1", reference="TXN-1")

    assert entry.sequence == 1
    assert entry.outcome == "SUCCESS"
    assert log.verify_chain() is True
