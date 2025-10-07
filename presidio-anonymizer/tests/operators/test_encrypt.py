import pytest

from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators.encrypt import Encrypt
from presidio_anonymizer.operators.aes_cipher import AESCipher
from presidio_anonymizer.operators.operator import OperatorType


# --- Task 2: operator name/type --------------------------------------------------

def test_operator_name():
    op = Encrypt()
    assert op.operator_name() == "encrypt"


def test_operator_type():
    op = Encrypt()
    assert op.operator_type() == OperatorType.Anonymize


# --- Task 3: mock invalid-key path for 100% coverage -----------------------------

def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mocker):
    """
    b'1111111111111111' is valid (128 bit). Force the error path by making
    AESCipher.is_valid_key_size() return False so validate() raises.
    """
    mocker.patch.object(AESCipher, "is_valid_key_size", return_value=False)

    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b"1111111111111111"})


# --- Task 4: parametrize valid key sizes -----------------------------------------

@pytest.mark.parametrize(
    "key",
    [
        "a" * 16,   # 128-bit string
        "a" * 24,   # 192-bit string
        "a" * 32,   # 256-bit string
        b"a" * 16,  # 128-bit bytes
        b"a" * 24,  # 192-bit bytes
        b"a" * 32,  # 256-bit bytes
    ],
)
def test_valid_keys(key):
    # should NOT raise
    Encrypt().validate(params={"key": key})
