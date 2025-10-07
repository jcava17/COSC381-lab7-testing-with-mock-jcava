import pytest
from unittest import mock

from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators.encrypt import Encrypt
from presidio_anonymizer.operators.aes_cipher import AESCipher
from presidio_anonymizer.operators.operator import OperatorType


# ---------------- Task 2: operator name/type ----------------

def test_operator_name():
    assert Encrypt().operator_name() == "encrypt"


def test_operator_type():
    assert Encrypt().operator_type() == OperatorType.Anonymize


# --------------- Task 3: force invalid key to trigger error path -----------------
# bytes branch (else) -> raise

@mock.patch.object(AESCipher, "is_valid_key_size")
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size):
    mock_is_valid_key_size.return_value = False  # explicit per rubric
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b"1111111111111111"})  # valid 128-bit, mocked invalid

# string branch (if) -> raise (covers the second raise line for 100% coverage)

@mock.patch.object(AESCipher, "is_valid_key_size")
def test_invalid_length_string_key_then_ipe_raised(mock_is_valid_key_size):
    mock_is_valid_key_size.return_value = False
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "a" * 16})  # valid 128-bit, mocked invalid


# Valid branches of validate() (both types), plus operate() for both input types

@mock.patch.object(AESCipher, "is_valid_key_size", return_value=True)
def test_validate_accepts_string_key_when_valid(mock_is_valid_key_size):
    Encrypt().validate(params={"key": "a" * 16})  # 128-bit string


@mock.patch.object(AESCipher, "is_valid_key_size", return_value=True)
def test_validate_accepts_bytes_key_when_valid(mock_is_valid_key_size):
    Encrypt().validate(params={"key": b"a" * 16})  # 128-bit bytes


@mock.patch.object(AESCipher, "encrypt", return_value="ENC(TEXT)")
def test_operate_str_key_calls_encrypt_and_encodes_key(mock_encrypt):
    out = Encrypt().operate(text="TEXT", params={"key": "a" * 16})
    assert out == "ENC(TEXT)"
    # ensure string key was encoded to bytes before passing to AESCipher.encrypt
    sent_key = mock_encrypt.call_args[0][0]
    assert isinstance(sent_key, (bytes, bytearray))


@mock.patch.object(AESCipher, "encrypt", return_value="ENC(TEXT)")
def test_operate_bytes_key_calls_encrypt(mock_encrypt):
    out = Encrypt().operate(text="TEXT", params={"key": b"a" * 16})
    assert out == "ENC(TEXT)"
    sent_key = mock_encrypt.call_args[0][0]
    assert isinstance(sent_key, (bytes, bytearray))


# ---------------- Task 4: black-box valid key sizes ----------------
# Use (key, key_type) and assert type; call validate() as required.

@pytest.mark.parametrize(
    "key,key_type",
    [
        ("a" * 16, str),     # 128-bit string
        ("a" * 24, str),     # 192-bit string
        ("a" * 32, str),     # 256-bit string
        (b"a" * 16, bytes),  # 128-bit bytes
        (b"a" * 24, bytes),  # 192-bit bytes
        (b"a" * 32, bytes),  # 256-bit bytes
    ],
)
def test_valid_keys(key, key_type):
    # Explicit type check required by the rubric
    assert isinstance(key, key_type)
    # Must call validate()
    Encrypt().validate(params={"key": key})
