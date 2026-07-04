import pytest

from passkit import testing as T
from passkit._cose import ALG_ES256
from passkit.attestation import (
    AttestationPolicy,
    check_attestation_policy,
    evaluate_attestation,
    known_aaguids,
    lookup,
    normalize_aaguid,
    parse_attestation_object,
)
from passkit.errors import AttestationError

RP = "example.mil"
ORIGIN = "https://example.mil"
YUBI = "ee882879721c491397753dfcce97072a"


def _packed(aaguid_hex=YUBI):
    import os
    _, att, _ = T.build_registration(
        RP, ORIGIN, os.urandom(32), fmt="packed", aaguid=bytes.fromhex(aaguid_hex)
    )
    return parse_attestation_object(att)


def _none(aaguid_hex="00000000000000000000000000000000"):
    import os
    _, att, _ = T.build_registration(
        RP, ORIGIN, os.urandom(32), aaguid=bytes.fromhex(aaguid_hex)
    )
    return parse_attestation_object(att)


def test_parse_none_format():
    obj = _none()
    assert obj.fmt == "none"
    assert obj.att_stmt == {}
    assert obj.auth_data.has_attested_credential_data


def test_evaluate_none():
    ev = evaluate_attestation(_none())
    assert ev.attestation_type == "none"
    assert not ev.signature_present


def test_evaluate_packed_self():
    ev = evaluate_attestation(_packed())
    assert ev.fmt == "packed"
    assert ev.attestation_type == "self"
    assert ev.signature_present
    assert ev.algorithm == ALG_ES256


def test_parse_rejects_non_map():
    with pytest.raises(AttestationError):
        parse_attestation_object(b"\x01")


def test_parse_rejects_missing_authdata():
    from passkit import _cbor
    bad = _cbor.dumps({"fmt": "none", "attStmt": {}})
    with pytest.raises(AttestationError):
        parse_attestation_object(bad)


def test_aaguid_surfaced():
    obj = _packed()
    assert obj.aaguid_hex == YUBI


# --- metadata ---

def test_metadata_lookup_known():
    info = lookup(YUBI)
    assert info is not None
    assert info.hardware_backed


def test_metadata_lookup_unknown_returns_none():
    assert lookup("11" * 16) is None


def test_metadata_extra_override():
    from passkit.attestation.metadata import AuthenticatorInfo
    extra = {"11" * 16: AuthenticatorInfo(name="Custom", hardware_backed=True, user_verification=True)}
    info = lookup("11" * 16, extra=extra)
    assert info.name == "Custom"


def test_normalize_aaguid_from_bytes_and_dashes():
    assert normalize_aaguid(bytes(range(16))) == bytes(range(16)).hex()
    assert normalize_aaguid("EE882879-721C-4913-9775-3DFCCE97072A") == YUBI


def test_known_aaguids_is_copy():
    a = known_aaguids()
    a.clear()
    assert known_aaguids()  # original untouched


# --- policy ---

def test_policy_allows_listed_aaguid():
    res = check_attestation_policy(
        _packed(), AttestationPolicy(allowed_aaguids=[YUBI], require_user_verification=True)
    )
    assert res.allowed


def test_policy_denies_unlisted_aaguid():
    res = check_attestation_policy(_packed(), AttestationPolicy(allowed_aaguids=["ab" * 16]))
    assert not res.allowed


def test_policy_denies_explicit_aaguid():
    res = check_attestation_policy(_packed(), AttestationPolicy(denied_aaguids=[YUBI]))
    assert not res.allowed


def test_policy_requires_uv():
    import os
    _, att, _ = T.build_registration(RP, ORIGIN, os.urandom(32), uv=False,
                                     fmt="packed", aaguid=bytes.fromhex(YUBI))
    obj = parse_attestation_object(att)
    res = check_attestation_policy(obj, AttestationPolicy(require_user_verification=True))
    assert not res.allowed


def test_policy_format_restriction():
    res = check_attestation_policy(_none(), AttestationPolicy(allowed_formats=["packed"]))
    assert not res.allowed


def test_policy_allowlist_but_zero_aaguid_denied():
    res = check_attestation_policy(_none(), AttestationPolicy(allowed_aaguids=[YUBI]))
    assert not res.allowed
