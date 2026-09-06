from validation_service.masking import mask_card_number, mask_ssn


def test_masks_all_but_last_four_of_ssn():
    assert mask_ssn("123-45-6789") == "***-**-6789"


def test_masks_sixteen_digit_card_number():
    assert mask_card_number("4111 1111 1111 1111") == "************1111"
