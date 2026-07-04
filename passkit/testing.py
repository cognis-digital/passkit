"""Test-vector generation helpers.

Builds *valid* WebAuthn ceremony artifacts (and lets tests tamper with them)
using the ``cryptography`` library, so the verifier can be exercised against
known-good and known-bad inputs deterministically and offline. These helpers
live in the package (not just tests/) so downstream users can build fixtures
for their own integration tests.
"""

from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from passkit import _cbor
from passkit._cose import (
    ALG_ES256,
    ALG_RS256,
    public_key_to_cose,
)
from passkit._util import b64url_encode, rp_id_hash, sha256
from passkit.webauthn.authdata import FLAG_AT, FLAG_UP, FLAG_UV


@dataclass
class GeneratedCredential:
    private_key: object
    alg: int
    credential_id: bytes
    aaguid: bytes
    cose_public_key: bytes


def generate_credential(
    alg: int = ALG_ES256,
    aaguid: Optional[bytes] = None,
    credential_id: Optional[bytes] = None,
) -> GeneratedCredential:
    if alg == ALG_ES256:
        priv = ec.generate_private_key(ec.SECP256R1())
    elif alg == ALG_RS256:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        raise ValueError(f"unsupported alg {alg}")
    cose = public_key_to_cose(priv.public_key(), alg)
    return GeneratedCredential(
        private_key=priv,
        alg=alg,
        credential_id=credential_id or os.urandom(32),
        aaguid=aaguid or bytes(16),
        cose_public_key=cose,
    )


def make_client_data(
    ctype: str, challenge: bytes, origin: str, cross_origin: bool = False
) -> bytes:
    obj = {
        "type": ctype,
        "challenge": b64url_encode(challenge),
        "origin": origin,
        "crossOrigin": cross_origin,
    }
    return json.dumps(obj).encode("utf-8")


def make_authenticator_data(
    rp_id: str,
    *,
    sign_count: int = 0,
    up: bool = True,
    uv: bool = True,
    attested: Optional[GeneratedCredential] = None,
    extra_flags: int = 0,
) -> bytes:
    flags = extra_flags
    if up:
        flags |= FLAG_UP
    if uv:
        flags |= FLAG_UV
    body = rp_id_hash(rp_id)
    body += bytes([flags])
    body += struct.pack(">I", sign_count)
    if attested is not None:
        flags |= FLAG_AT
        body = rp_id_hash(rp_id) + bytes([flags]) + struct.pack(">I", sign_count)
        body += attested.aaguid
        body += struct.pack(">H", len(attested.credential_id))
        body += attested.credential_id
        body += attested.cose_public_key
    return body


def make_attestation_object(
    auth_data: bytes, fmt: str = "none", att_stmt: Optional[dict] = None
) -> bytes:
    obj = {
        "fmt": fmt,
        "attStmt": att_stmt if att_stmt is not None else {},
        "authData": auth_data,
    }
    return _cbor.dumps(obj)


def sign_assertion(
    cred: GeneratedCredential, auth_data: bytes, client_data_json: bytes
) -> bytes:
    message = auth_data + sha256(client_data_json)
    if cred.alg == ALG_ES256:
        return cred.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    if cred.alg == ALG_RS256:
        return cred.private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    raise ValueError("unsupported alg")


def build_registration(
    rp_id: str,
    origin: str,
    challenge: bytes,
    *,
    alg: int = ALG_ES256,
    uv: bool = True,
    sign_count: int = 0,
    aaguid: Optional[bytes] = None,
    fmt: str = "none",
) -> Tuple[GeneratedCredential, bytes, bytes]:
    """Return (credential, attestation_object, client_data_json)."""
    cred = generate_credential(alg=alg, aaguid=aaguid)
    authd = make_authenticator_data(
        rp_id, sign_count=sign_count, uv=uv, attested=cred
    )
    att_stmt = None
    if fmt == "packed":
        # self-attestation: sign authData||clientHash with the credential key
        client_data = make_client_data("webauthn.create", challenge, origin)
        sig = _self_sign(cred, authd, client_data)
        att_stmt = {"alg": cred.alg, "sig": sig}
        att_obj = make_attestation_object(authd, fmt="packed", att_stmt=att_stmt)
        return cred, att_obj, client_data
    client_data = make_client_data("webauthn.create", challenge, origin)
    att_obj = make_attestation_object(authd, fmt=fmt, att_stmt=att_stmt)
    return cred, att_obj, client_data


def _self_sign(cred: GeneratedCredential, auth_data: bytes, client_data: bytes) -> bytes:
    message = auth_data + sha256(client_data)
    if cred.alg == ALG_ES256:
        return cred.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return cred.private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def build_assertion(
    cred: GeneratedCredential,
    rp_id: str,
    origin: str,
    challenge: bytes,
    *,
    uv: bool = True,
    sign_count: int = 1,
) -> Tuple[bytes, bytes, bytes]:
    """Return (authenticator_data, client_data_json, signature)."""
    authd = make_authenticator_data(rp_id, sign_count=sign_count, uv=uv)
    client_data = make_client_data("webauthn.get", challenge, origin)
    sig = sign_assertion(cred, authd, client_data)
    return authd, client_data, sig


__all__ = [
    "GeneratedCredential",
    "generate_credential",
    "make_client_data",
    "make_authenticator_data",
    "make_attestation_object",
    "sign_assertion",
    "build_registration",
    "build_assertion",
]
