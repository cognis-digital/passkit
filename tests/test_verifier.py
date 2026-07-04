import os

import pytest

from passkit import testing as T
from passkit._cose import ALG_ES256, ALG_RS256
from passkit.errors import VerificationError
from passkit.webauthn import verify_assertion, verify_registration

RP = "login.example.mil"
ORIGIN = "https://login.example.mil"


# --- registration: happy paths ---------------------------------------------

def test_registration_es256_valid(es256_registration):
    cred, att, cd, chal = es256_registration
    res = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
    )
    assert res.credential_id == cred.credential_id
    assert res.user_present


def test_registration_rs256_valid(rs256_registration):
    cred, att, cd, chal = rs256_registration
    res = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
    )
    assert res.credential_public_key == cred.cose_public_key


def test_registration_require_uv_pass(challenge):
    cred, att, cd = T.build_registration(RP, ORIGIN, challenge, uv=True)
    res = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=challenge, expected_origins=[ORIGIN], rp_id=RP,
        require_user_verification=True,
    )
    assert res.user_verified


def test_registration_multiple_allowed_origins(challenge):
    cred, att, cd = T.build_registration(RP, ORIGIN, challenge)
    res = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=challenge,
        expected_origins=["https://other.example.mil", ORIGIN],
        rp_id=RP,
    )
    assert res.credential_id == cred.credential_id


def test_registration_default_port_equivalence(challenge):
    cred, att, cd = T.build_registration(RP, ORIGIN, challenge)
    res = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=challenge,
        expected_origins=["https://login.example.mil:443"],
        rp_id=RP,
    )
    assert res.credential_id == cred.credential_id


# --- registration: rejections -----------------------------------------------

def test_registration_wrong_challenge(es256_registration):
    _, att, cd, _ = es256_registration
    with pytest.raises(VerificationError) as e:
        verify_registration(
            attestation_object=att, client_data_json=cd,
            expected_challenge=os.urandom(32), expected_origins=[ORIGIN], rp_id=RP,
        )
    assert e.value.code == "challenge_mismatch"


def test_registration_wrong_origin(es256_registration):
    _, att, cd, chal = es256_registration
    with pytest.raises(VerificationError) as e:
        verify_registration(
            attestation_object=att, client_data_json=cd,
            expected_challenge=chal, expected_origins=["https://evil.example.mil"],
            rp_id=RP,
        )
    assert e.value.code == "origin_mismatch"


def test_registration_wrong_rp_id(es256_registration):
    _, att, cd, chal = es256_registration
    with pytest.raises(VerificationError) as e:
        verify_registration(
            attestation_object=att, client_data_json=cd,
            expected_challenge=chal, expected_origins=[ORIGIN], rp_id="other.mil",
        )
    assert e.value.code == "rpid_mismatch"


def test_registration_require_uv_but_absent(challenge):
    cred, att, cd = T.build_registration(RP, ORIGIN, challenge, uv=False)
    with pytest.raises(VerificationError) as e:
        verify_registration(
            attestation_object=att, client_data_json=cd,
            expected_challenge=challenge, expected_origins=[ORIGIN], rp_id=RP,
            require_user_verification=True,
        )
    assert e.value.code == "uv_required"


def test_registration_wrong_client_data_type(challenge):
    # build an assertion-typed clientData for a registration
    cred = T.generate_credential()
    ad = T.make_authenticator_data(RP, attested=cred)
    att = T.make_attestation_object(ad)
    cd = T.make_client_data("webauthn.get", challenge, ORIGIN)
    with pytest.raises(VerificationError) as e:
        verify_registration(
            attestation_object=att, client_data_json=cd,
            expected_challenge=challenge, expected_origins=[ORIGIN], rp_id=RP,
        )
    assert e.value.code == "bad_type"


def test_registration_no_up_flag(challenge):
    cred = T.generate_credential()
    ad = T.make_authenticator_data(RP, up=False, uv=False, attested=cred)
    att = T.make_attestation_object(ad)
    cd = T.make_client_data("webauthn.create", challenge, ORIGIN)
    with pytest.raises(VerificationError) as e:
        verify_registration(
            attestation_object=att, client_data_json=cd,
            expected_challenge=challenge, expected_origins=[ORIGIN], rp_id=RP,
        )
    assert e.value.code == "up_missing"


# --- assertion: happy paths -------------------------------------------------

def _register(challenge, alg=ALG_ES256):
    cred, att, cd = T.build_registration(RP, ORIGIN, challenge, alg=alg)
    res = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=challenge, expected_origins=[ORIGIN], rp_id=RP,
    )
    return cred, res


def test_assertion_es256_valid():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal, sign_count=5)
    res = verify_assertion(
        credential_public_key=reg.credential_public_key,
        authenticator_data=ad, client_data_json=cd, signature=sig,
        expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
        stored_sign_count=1,
    )
    assert res.new_sign_count == 5
    assert not res.clone_warning


def test_assertion_rs256_valid():
    cred, reg = _register(os.urandom(32), alg=ALG_RS256)
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal, sign_count=2)
    res = verify_assertion(
        credential_public_key=reg.credential_public_key,
        authenticator_data=ad, client_data_json=cd, signature=sig,
        expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
    )
    assert res.new_sign_count == 2


# --- assertion: security rejections ----------------------------------------

def test_assertion_phishing_relayed_origin_rejected():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    # attacker relays the ceremony from a lookalike domain
    ad, cd, sig = T.build_assertion(cred, RP, "https://login.examp1e.mil", chal)
    with pytest.raises(VerificationError) as e:
        verify_assertion(
            credential_public_key=reg.credential_public_key,
            authenticator_data=ad, client_data_json=cd, signature=sig,
            expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
        )
    assert e.value.code == "origin_mismatch"


def test_assertion_replayed_challenge_rejected():
    cred, reg = _register(os.urandom(32))
    used = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, used)
    # verifier now expects a fresh challenge, not the replayed one
    with pytest.raises(VerificationError) as e:
        verify_assertion(
            credential_public_key=reg.credential_public_key,
            authenticator_data=ad, client_data_json=cd, signature=sig,
            expected_challenge=os.urandom(32), expected_origins=[ORIGIN], rp_id=RP,
        )
    assert e.value.code == "challenge_mismatch"


def test_assertion_tampered_authdata_rejected():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal)
    tampered = bytearray(ad)
    tampered[33] ^= 0xFF  # flip a sign-count byte -> breaks signature
    with pytest.raises(VerificationError) as e:
        verify_assertion(
            credential_public_key=reg.credential_public_key,
            authenticator_data=bytes(tampered), client_data_json=cd, signature=sig,
            expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
        )
    assert e.value.code == "bad_signature"


def test_assertion_wrong_key_rejected():
    cred, reg = _register(os.urandom(32))
    other = T.generate_credential()
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal)
    with pytest.raises(VerificationError) as e:
        verify_assertion(
            credential_public_key=other.cose_public_key,
            authenticator_data=ad, client_data_json=cd, signature=sig,
            expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
        )
    assert e.value.code == "bad_signature"


def test_assertion_clone_detected_on_stale_counter():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal, sign_count=5)
    res = verify_assertion(
        credential_public_key=reg.credential_public_key,
        authenticator_data=ad, client_data_json=cd, signature=sig,
        expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
        stored_sign_count=5,  # counter did not advance
    )
    assert res.clone_warning
    assert res.warnings


def test_assertion_counter_zero_no_clone_warning():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal, sign_count=0)
    res = verify_assertion(
        credential_public_key=reg.credential_public_key,
        authenticator_data=ad, client_data_json=cd, signature=sig,
        expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
        stored_sign_count=0,
    )
    assert not res.clone_warning


def test_assertion_require_uv_but_absent():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal, uv=False)
    with pytest.raises(VerificationError) as e:
        verify_assertion(
            credential_public_key=reg.credential_public_key,
            authenticator_data=ad, client_data_json=cd, signature=sig,
            expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
            require_user_verification=True,
        )
    assert e.value.code == "uv_required"


def test_assertion_wrong_type_rejected():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    ad = T.make_authenticator_data(RP, sign_count=1)
    cd = T.make_client_data("webauthn.create", chal, ORIGIN)  # wrong type
    sig = T.sign_assertion(cred, ad, cd)
    with pytest.raises(VerificationError) as e:
        verify_assertion(
            credential_public_key=reg.credential_public_key,
            authenticator_data=ad, client_data_json=cd, signature=sig,
            expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
        )
    assert e.value.code == "bad_type"


def test_assertion_credential_id_mismatch_rejected():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal)
    with pytest.raises(VerificationError) as e:
        verify_assertion(
            credential_public_key=reg.credential_public_key,
            authenticator_data=ad, client_data_json=cd, signature=sig,
            expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
            credential_id=b"aaaa", expected_credential_id=b"bbbb",
        )
    assert e.value.code == "cred_mismatch"


def test_assertion_wrong_rp_id_rejected():
    cred, reg = _register(os.urandom(32))
    chal = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal)
    with pytest.raises(VerificationError) as e:
        verify_assertion(
            credential_public_key=reg.credential_public_key,
            authenticator_data=ad, client_data_json=cd, signature=sig,
            expected_challenge=chal, expected_origins=[ORIGIN], rp_id="evil.mil",
        )
    assert e.value.code == "rpid_mismatch"
