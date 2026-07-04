import json

import pytest

from passkit import testing as T
from passkit._util import b64url_decode
from passkit.errors import VerificationError
from passkit.webauthn.clientdata import parse_client_data


def test_parse_valid():
    chal = b"\x01\x02\x03\x04"
    cd = T.make_client_data("webauthn.get", chal, "https://ex.com", cross_origin=True)
    parsed = parse_client_data(cd)
    assert parsed.type == "webauthn.get"
    assert parsed.challenge == chal
    assert parsed.origin == "https://ex.com"
    assert parsed.cross_origin is True


def test_invalid_json():
    with pytest.raises(VerificationError) as e:
        parse_client_data(b"{not json")
    assert e.value.code == "bad_clientdata"


def test_not_an_object():
    with pytest.raises(VerificationError):
        parse_client_data(b"[1,2,3]")


def test_missing_type():
    cd = json.dumps({"challenge": "AAAA", "origin": "https://x"}).encode()
    with pytest.raises(VerificationError):
        parse_client_data(cd)


def test_missing_challenge():
    cd = json.dumps({"type": "webauthn.get", "origin": "https://x"}).encode()
    with pytest.raises(VerificationError):
        parse_client_data(cd)


def test_bad_base64url_challenge():
    # length not a multiple of 4 after padding-normalization -> binascii.Error
    cd = json.dumps({"type": "webauthn.get", "challenge": "AAAAA", "origin": "https://x"}).encode()
    with pytest.raises(VerificationError):
        parse_client_data(cd)


def test_bad_cross_origin_type():
    cd = json.dumps({"type": "webauthn.get", "challenge": "AAAA",
                     "origin": "https://x", "crossOrigin": "yes"}).encode()
    with pytest.raises(VerificationError):
        parse_client_data(cd)


def test_b64url_decode_padding_variants():
    assert b64url_decode("AAAA") == b"\x00\x00\x00"
    assert b64url_decode("AAA") == b"\x00\x00"
