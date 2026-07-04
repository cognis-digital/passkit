import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from passkit import _cose
from passkit._cose import ALG_ES256, ALG_RS256, COSEError, parse_cose_key, verify_signature


def _es256_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, _cose.public_key_to_cose(priv.public_key(), ALG_ES256)


def _rs256_key():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, _cose.public_key_to_cose(priv.public_key(), ALG_RS256)


def test_parse_es256_key():
    _, cose = _es256_key()
    key = parse_cose_key(cose)
    assert key.alg == ALG_ES256
    assert key.alg_name == "ES256"


def test_parse_rs256_key():
    _, cose = _rs256_key()
    key = parse_cose_key(cose)
    assert key.alg == ALG_RS256
    assert key.alg_name == "RS256"


def test_es256_signature_valid():
    priv, cose = _es256_key()
    key = parse_cose_key(cose)
    msg = b"attestationData||clientHash"
    sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    assert verify_signature(key, msg, sig) is True


def test_es256_signature_tampered_message():
    priv, cose = _es256_key()
    key = parse_cose_key(cose)
    sig = priv.sign(b"original", ec.ECDSA(hashes.SHA256()))
    assert verify_signature(key, b"tampered", sig) is False


def test_es256_signature_tampered_signature():
    priv, cose = _es256_key()
    key = parse_cose_key(cose)
    sig = bytearray(priv.sign(b"m", ec.ECDSA(hashes.SHA256())))
    sig[-1] ^= 0xFF
    assert verify_signature(key, b"m", bytes(sig)) is False


def test_rs256_signature_valid():
    priv, cose = _rs256_key()
    key = parse_cose_key(cose)
    msg = b"hello"
    sig = priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    assert verify_signature(key, msg, sig) is True


def test_rs256_signature_invalid():
    priv, cose = _rs256_key()
    key = parse_cose_key(cose)
    sig = priv.sign(b"m", padding.PKCS1v15(), hashes.SHA256())
    assert verify_signature(key, b"other", sig) is False


def test_reject_unsupported_kty():
    with pytest.raises(COSEError):
        parse_cose_key({1: 99, 3: -7})


def test_reject_missing_alg():
    with pytest.raises(COSEError):
        parse_cose_key({1: 2})


def test_reject_unsupported_ec_curve():
    with pytest.raises(COSEError):
        parse_cose_key({1: 2, 3: -7, -1: 2, -2: b"\x00" * 32, -3: b"\x00" * 32})


def test_reject_bad_ec_coordinate_length():
    with pytest.raises(COSEError):
        parse_cose_key({1: 2, 3: -7, -1: 1, -2: b"\x00" * 16, -3: b"\x00" * 32})


def test_reject_small_rsa_modulus():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    numbers = priv.public_key().public_numbers()
    n_len = (numbers.n.bit_length() + 7) // 8
    cose = {1: 3, 3: -257, -1: numbers.n.to_bytes(n_len, "big"), -2: numbers.e.to_bytes(3, "big")}
    with pytest.raises(COSEError):
        parse_cose_key(cose)


def test_reject_ec_wrong_alg():
    with pytest.raises(COSEError):
        parse_cose_key({1: 2, 3: -257, -1: 1, -2: b"\x00" * 32, -3: b"\x00" * 32})
