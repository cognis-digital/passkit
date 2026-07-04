"""WebAuthn/FIDO2 registration and assertion verifiers.

This is the security core of passkit. Both verifiers implement the checks
required by the W3C WebAuthn spec, in particular the ones that give WebAuthn
its phishing resistance:

  * challenge binding  - the signed challenge must equal the one we issued
  * origin binding     - the signed origin must be an allowed RP origin, so a
                         lookalike phishing domain cannot relay the ceremony
  * rpIdHash binding   - authenticatorData.rpIdHash must be SHA-256(rp_id)
  * signature          - the assertion must verify against the *registered*
                         credential public key
  * signCount          - monotonic counter check detects cloned authenticators

Inputs are the raw ceremony artifacts (bytes), so this works for any transport
(JSON API, gRPC, air-gapped file drop) without assuming a web framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from passkit import _cose
from passkit._util import (
    b64url_encode,
    constant_time_equals,
    normalize_origin,
    rp_id_hash,
    sha256,
)
from passkit.errors import VerificationError
from passkit.webauthn.authdata import AuthenticatorData, parse_authenticator_data
from passkit.webauthn.clientdata import ClientData, parse_client_data

TYPE_CREATE = "webauthn.create"
TYPE_GET = "webauthn.get"


@dataclass
class RegistrationResult:
    """Outcome of a successful registration verification."""

    credential_id: bytes
    credential_public_key: bytes  # COSE_Key CBOR bytes; store this
    sign_count: int
    aaguid: bytes
    user_present: bool
    user_verified: bool
    backup_eligible: bool
    backup_state: bool
    fmt: Optional[str] = None
    authenticator_data: Optional[AuthenticatorData] = None
    client_data: Optional[ClientData] = None

    @property
    def credential_id_b64(self) -> str:
        return b64url_encode(self.credential_id)

    @property
    def aaguid_hex(self) -> str:
        return self.aaguid.hex()


@dataclass
class AssertionResult:
    """Outcome of a successful assertion (login) verification."""

    credential_id: bytes
    new_sign_count: int
    user_present: bool
    user_verified: bool
    backup_eligible: bool
    backup_state: bool
    clone_warning: bool = False
    warnings: List[str] = field(default_factory=list)
    authenticator_data: Optional[AuthenticatorData] = None
    client_data: Optional[ClientData] = None


def _check_origin(client_data: ClientData, expected_origins: Sequence[str]) -> None:
    if not expected_origins:
        raise VerificationError("no expected origins configured", "config")
    try:
        got = normalize_origin(client_data.origin)
    except ValueError as exc:
        raise VerificationError(
            f"clientData.origin is not a valid origin: {exc}", "bad_origin"
        ) from exc
    allowed = set()
    for origin in expected_origins:
        try:
            allowed.add(normalize_origin(origin))
        except ValueError as exc:
            raise VerificationError(
                f"configured expected origin invalid: {origin!r}", "config"
            ) from exc
    if got not in allowed:
        # This is the phishing-resistance gate: a relayed ceremony from a
        # lookalike domain lands here and is rejected.
        raise VerificationError(
            f"origin mismatch: signed origin {got!r} not in allowed origins "
            f"{sorted(allowed)!r} (possible phishing/relay)",
            "origin_mismatch",
        )


def _check_challenge(client_data: ClientData, expected_challenge: bytes) -> None:
    if not expected_challenge:
        raise VerificationError("no expected challenge provided", "config")
    if not constant_time_equals(client_data.challenge, expected_challenge):
        raise VerificationError(
            "challenge mismatch (stale, replayed, or relayed ceremony)",
            "challenge_mismatch",
        )


def _check_rp_id_hash(authdata: AuthenticatorData, rp_id: str) -> None:
    expected = rp_id_hash(rp_id)
    if not constant_time_equals(authdata.rp_id_hash, expected):
        raise VerificationError(
            f"rpIdHash mismatch: authenticator signed for a different RP than "
            f"{rp_id!r}",
            "rpid_mismatch",
        )


def verify_registration(
    *,
    attestation_object: bytes,
    client_data_json: bytes,
    expected_challenge: bytes,
    expected_origins: Sequence[str],
    rp_id: str,
    require_user_verification: bool = False,
) -> RegistrationResult:
    """Verify a WebAuthn registration (navigator.credentials.create) response.

    Args:
        attestation_object: raw CBOR attestation object bytes.
        client_data_json: raw clientDataJSON bytes.
        expected_challenge: the exact challenge bytes issued to this ceremony.
        expected_origins: allowed RP origins (e.g. ["https://login.example.mil"]).
        rp_id: the Relying Party ID (e.g. "example.mil").
        require_user_verification: enforce the UV flag.

    Returns a RegistrationResult whose credential_public_key you persist for
    later assertion verification. Raises VerificationError on any failure.
    """
    from passkit.attestation.parser import parse_attestation_object

    client_data = parse_client_data(client_data_json)
    if client_data.type != TYPE_CREATE:
        raise VerificationError(
            f"clientData.type is {client_data.type!r}, expected {TYPE_CREATE!r}",
            "bad_type",
        )
    _check_challenge(client_data, expected_challenge)
    _check_origin(client_data, expected_origins)

    att = parse_attestation_object(attestation_object)
    authdata = att.auth_data
    _check_rp_id_hash(authdata, rp_id)

    if not authdata.user_present:
        raise VerificationError("user-present (UP) flag not set", "up_missing")
    if require_user_verification and not authdata.user_verified:
        raise VerificationError(
            "user verification required but UV flag not set", "uv_required"
        )
    if not authdata.has_attested_credential_data or authdata.attested_credential_data is None:
        raise VerificationError(
            "registration authenticatorData has no attested credential data",
            "no_attested_data",
        )

    acd = authdata.attested_credential_data
    # Validate the COSE key parses and is a supported algorithm now, so we
    # never persist a credential we cannot later verify against.
    _cose.parse_cose_key(acd.credential_public_key)

    return RegistrationResult(
        credential_id=acd.credential_id,
        credential_public_key=acd.credential_public_key,
        sign_count=authdata.sign_count,
        aaguid=acd.aaguid,
        user_present=authdata.user_present,
        user_verified=authdata.user_verified,
        backup_eligible=authdata.backup_eligible,
        backup_state=authdata.backup_state,
        fmt=att.fmt,
        authenticator_data=authdata,
        client_data=client_data,
    )


def verify_assertion(
    *,
    credential_public_key: bytes,
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
    expected_challenge: bytes,
    expected_origins: Sequence[str],
    rp_id: str,
    stored_sign_count: int = 0,
    require_user_verification: bool = False,
    credential_id: Optional[bytes] = None,
    expected_credential_id: Optional[bytes] = None,
) -> AssertionResult:
    """Verify a WebAuthn assertion (navigator.credentials.get) response.

    Args:
        credential_public_key: COSE_Key bytes stored at registration.
        authenticator_data: raw authenticatorData bytes from the assertion.
        client_data_json: raw clientDataJSON bytes.
        signature: the assertion signature bytes.
        expected_challenge: challenge bytes issued for this login.
        expected_origins: allowed RP origins.
        rp_id: Relying Party ID.
        stored_sign_count: last-seen counter for this credential (0 if unused).
        require_user_verification: enforce the UV flag.
        credential_id / expected_credential_id: if both given, must match.

    Returns an AssertionResult. Persist ``new_sign_count``. Raises
    VerificationError on any failure. ``clone_warning`` flags a non-monotonic
    counter (possible cloned authenticator) per the spec's guidance.
    """
    if (
        credential_id is not None
        and expected_credential_id is not None
        and not constant_time_equals(credential_id, expected_credential_id)
    ):
        raise VerificationError(
            "credentialId does not match the selected credential", "cred_mismatch"
        )

    client_data = parse_client_data(client_data_json)
    if client_data.type != TYPE_GET:
        raise VerificationError(
            f"clientData.type is {client_data.type!r}, expected {TYPE_GET!r}",
            "bad_type",
        )
    _check_challenge(client_data, expected_challenge)
    _check_origin(client_data, expected_origins)

    authdata = parse_authenticator_data(authenticator_data)
    _check_rp_id_hash(authdata, rp_id)

    if not authdata.user_present:
        raise VerificationError("user-present (UP) flag not set", "up_missing")
    if require_user_verification and not authdata.user_verified:
        raise VerificationError(
            "user verification required but UV flag not set", "uv_required"
        )

    # Signature is over authenticatorData || SHA-256(clientDataJSON).
    signed_message = bytes(authenticator_data) + sha256(client_data.raw)
    key = _cose.parse_cose_key(credential_public_key)
    if not _cose.verify_signature(key, signed_message, bytes(signature)):
        raise VerificationError(
            "assertion signature verification failed", "bad_signature"
        )

    warnings: List[str] = []
    clone_warning = False
    new_count = authdata.sign_count
    # signCount monotonicity: if either side is nonzero and the counter did not
    # advance, the authenticator may have been cloned (WebAuthn 7.2 step 21).
    if new_count != 0 or stored_sign_count != 0:
        if new_count <= stored_sign_count:
            clone_warning = True
            warnings.append(
                f"signCount did not increase ({new_count} <= {stored_sign_count}): "
                f"possible cloned authenticator"
            )

    return AssertionResult(
        credential_id=authdata.attested_credential_data.credential_id
        if authdata.attested_credential_data
        else (credential_id or b""),
        new_sign_count=new_count,
        user_present=authdata.user_present,
        user_verified=authdata.user_verified,
        backup_eligible=authdata.backup_eligible,
        backup_state=authdata.backup_state,
        clone_warning=clone_warning,
        warnings=warnings,
        authenticator_data=authdata,
        client_data=client_data,
    )


__all__ = [
    "verify_registration",
    "verify_assertion",
    "RegistrationResult",
    "AssertionResult",
    "TYPE_CREATE",
    "TYPE_GET",
]
