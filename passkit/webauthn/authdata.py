"""Parser for WebAuthn authenticatorData.

authenticatorData layout (see W3C WebAuthn Level 2, section 6.1):

    rpIdHash        32 bytes   SHA-256 of the RP ID
    flags            1 byte    bit field (below)
    signCount        4 bytes   big-endian unsigned counter
    attestedCredentialData  (present iff AT flag set)
        aaguid            16 bytes
        credentialIdLen    2 bytes  big-endian
        credentialId       L bytes
        credentialPublicKey  CBOR COSE_Key (variable)
    extensions      (present iff ED flag set)  CBOR map

Flag bits:
    0x01 UP  User Present
    0x04 UV  User Verified
    0x08 BE  Backup Eligible
    0x10 BS  Backup State
    0x40 AT  Attested credential data included
    0x80 ED  Extension data included
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from passkit._cbor import decode_first
from passkit.errors import VerificationError

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80


@dataclass
class AttestedCredentialData:
    aaguid: bytes
    credential_id: bytes
    credential_public_key: bytes  # raw COSE_Key CBOR bytes


@dataclass
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    attested_credential_data: Optional[AttestedCredentialData]
    extensions: Optional[Dict[Any, Any]]
    raw: bytes

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)

    @property
    def backup_eligible(self) -> bool:
        return bool(self.flags & FLAG_BE)

    @property
    def backup_state(self) -> bool:
        return bool(self.flags & FLAG_BS)

    @property
    def has_attested_credential_data(self) -> bool:
        return bool(self.flags & FLAG_AT)

    @property
    def has_extensions(self) -> bool:
        return bool(self.flags & FLAG_ED)


def parse_authenticator_data(data: bytes) -> AuthenticatorData:
    """Parse authenticatorData bytes into a structured object.

    Raises VerificationError (code ``bad_authdata``) on any structural fault.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise VerificationError("authenticatorData must be bytes", "bad_authdata")
    data = bytes(data)
    if len(data) < 37:
        raise VerificationError(
            "authenticatorData too short (need >= 37 bytes)", "bad_authdata"
        )

    rp_id_hash = data[0:32]
    flags = data[32]
    sign_count = int.from_bytes(data[33:37], "big")
    offset = 37

    attested: Optional[AttestedCredentialData] = None
    if flags & FLAG_AT:
        if len(data) < offset + 18:
            raise VerificationError(
                "authenticatorData truncated in attested credential data",
                "bad_authdata",
            )
        aaguid = data[offset:offset + 16]
        offset += 16
        cred_id_len = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        if len(data) < offset + cred_id_len:
            raise VerificationError(
                "authenticatorData truncated in credentialId", "bad_authdata"
            )
        credential_id = data[offset:offset + cred_id_len]
        offset += cred_id_len
        # The COSE key is a single CBOR item; decode it to find its length.
        try:
            _key, consumed = decode_first(data[offset:])
        except ValueError as exc:
            raise VerificationError(
                f"invalid COSE credential public key: {exc}", "bad_authdata"
            ) from exc
        credential_public_key = data[offset:offset + consumed]
        offset += consumed
        attested = AttestedCredentialData(
            aaguid=aaguid,
            credential_id=credential_id,
            credential_public_key=credential_public_key,
        )

    extensions: Optional[Dict[Any, Any]] = None
    if flags & FLAG_ED:
        try:
            ext, consumed = decode_first(data[offset:])
        except ValueError as exc:
            raise VerificationError(
                f"invalid extension data: {exc}", "bad_authdata"
            ) from exc
        if not isinstance(ext, dict):
            raise VerificationError("extension data is not a map", "bad_authdata")
        extensions = ext
        offset += consumed

    if offset != len(data):
        raise VerificationError(
            "trailing bytes after authenticatorData", "bad_authdata"
        )

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        attested_credential_data=attested,
        extensions=extensions,
        raw=data,
    )


__all__ = [
    "AuthenticatorData",
    "AttestedCredentialData",
    "parse_authenticator_data",
    "FLAG_UP",
    "FLAG_UV",
    "FLAG_BE",
    "FLAG_BS",
    "FLAG_AT",
    "FLAG_ED",
]
