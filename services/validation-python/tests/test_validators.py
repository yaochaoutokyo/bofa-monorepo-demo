from validation_service.validators import is_valid_email, is_valid_state, is_valid_zip


def test_accepts_well_formed_email():
    assert is_valid_email("jane.doe@example.com") is True


def test_accepts_known_state_and_zip():
    assert is_valid_state("ca") is True
    assert is_valid_zip("94105") is True

