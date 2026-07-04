import struct

import pytest

from passkit import testing as T
from passkit._util import rp_id_hash
from passkit.errors import VerificationError
from passkit.webauthn.authdata import parse_authenticator_data

RP = "example.mil"


def test_parse_minimal_authdata():
    ad = T.make_authenticator_data(RP, sign_count=7, up=True, uv=True)
    parsed = parse_authenticator_data(ad)
    assert parsed.rp_id_hash == rp_id_hash(RP)
    assert parsed.sign_count == 7
    assert parsed.user_present
    assert parsed.user_verified
    assert not parsed.has_attested_credential_data


def test_parse_with_attested_credential_data():
    cred = T.generate_credential()
    ad = T.make_authenticator_data(RP, attested=cred)
    parsed = parse_authenticator_data(ad)
    assert parsed.has_attested_credential_data
    acd = parsed.attested_credential_data
    assert acd.credential_id == cred.credential_id
    assert acd.credential_public_key == cred.cose_public_key


def test_flags_backup_bits():
    ad = T.make_authenticator_data(RP, up=True, uv=False, extra_flags=0x08 | 0x10)
    parsed = parse_authenticator_data(ad)
    assert parsed.backup_eligible
    assert parsed.backup_state
    assert not parsed.user_verified


def test_too_short_rejected():
    with pytest.raises(VerificationError) as exc:
        parse_authenticator_data(b"\x00" * 10)
    assert exc.value.code == "bad_authdata"


def test_truncated_attested_data_rejected():
    cred = T.generate_credential()
    ad = T.make_authenticator_data(RP, attested=cred)
    with pytest.raises(VerificationError):
        parse_authenticator_data(ad[:40])


def test_trailing_bytes_rejected():
    ad = T.make_authenticator_data(RP)
    with pytest.raises(VerificationError):
        parse_authenticator_data(ad + b"\xff\xff")


def test_non_bytes_rejected():
    with pytest.raises(VerificationError):
        parse_authenticator_data("not bytes")


def test_sign_count_big_endian():
    ad = T.make_authenticator_data(RP, sign_count=0x01020304)
    parsed = parse_authenticator_data(ad)
    assert parsed.sign_count == 0x01020304
    assert ad[33:37] == struct.pack(">I", 0x01020304)
