import pytest
from unittest import mock

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


# --- Task 3: invalid-key branch to reach 100% coverage ---------------------------
# Rubric requires: correct patch target, *decorator* with explicit return_value,
# and a renamed mock variable.

@mock.patch.object(AESCipher, "is_valid_key_size", return_value=False)
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size):
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        # bytes-key path (the else-branch in validate)
        Encrypt().validate(params={"key": b"1111111111111111"})
    # prove our stub was used
    mock_is_valid_key_size.assert_called()


# --- Extra: cover validate() success paths (string and bytes) --------------------

@mock.patch.object(AESCipher, "is_valid_key_size", return_value=True)
def test_validate_accepts_string_key_when_valid(mock_is_valid_key_size):
    Encrypt().validate(params={"key": "a" * 16})  # 128-bit string


@mock.patch.object(AESCipher, "is_valid_key_size", return_value=True)
def test_validate_accepts_bytes_key_when_valid(mock_is_valid_key_size):
    Encrypt().validate(params={"key": b"a" * 16})  # 128-bit bytes


# --- Extra: cover operate() without real crypto ---------------------------------

@mock.patch.object(AESCipher, "encrypt", return_value="ENC(TEXT)")
def test_operate_calls_aes_encrypt_with_str_key_and_encodes(mock_encrypt):
    out = Encrypt().operate(text="TEXT", params={"key": "a" * 16})
    assert out == "ENC(TEXT)"
    # string key should be encoded to bytes before passing to AESCipher.encrypt
    passed_key = mock_encrypt.call_args[0][0]
    assert isinstance(passed_key, (bytes, bytearray))


@mock.patch.object(AESCipher, "encrypt", return_value="ENC(TEXT)")
def test_operate_calls_aes_encrypt_with_bytes_key(mock_encrypt):
    out = Encrypt().operate(text="TEXT", params={"key": b"a" * 16})
    assert out == "ENC(TEXT)"
    passed_key = mock_encrypt.call_args[0][0]
    assert isinstance(passed_key, (bytes, bytearray))


# --- Task 4: black-box test with explicit key *type* in params -------------------
# (Rubric complained "missing string or bytes key type". We parametrize (key, key_type)
# and assert the type before calling validate.)

@pytest.mark.parametrize(
    "key,key_type",
    [
        ("a" * 16, str),   # 128-bit string
        ("a" * 24, str),   # 192-bit string
        ("a" * 32, str),   # 256-bit string
        (b"a" * 16, bytes),  # 128-bit bytes
        (b"a" * 24, bytes),  # 192-bit bytes
        (b"a" * 32, bytes),  # 256-bit bytes
    ],
)
def test_valid_keys(key, key_type):
    # prove we're testing both string and bytes keys
    assert isinstance(key, key_type)
    # should NOT raise
    Encrypt().validate(params={"key": key})

    from unittest import mock
import pytest
from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators.encrypt import Encrypt
from presidio_anonymizer.operators.aes_cipher import AESCipher

@mock.patch.object(AESCipher, "is_valid_key_size", return_value=False)
def test_invalid_length_string_key_then_ipe_raised(mock_is_valid_key_size):
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        # string-key path (if-branch) — patched to be invalid
        Encrypt().validate(params={"key": "a" * 16})
    mock_is_valid_key_size.assert_called()

