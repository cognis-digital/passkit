"""WebAuthn/FIDO2 verifier-side primitives."""

from passkit.webauthn.authdata import (
    AttestedCredentialData,
    AuthenticatorData,
    parse_authenticator_data,
)
from passkit.webauthn.clientdata import ClientData, parse_client_data
from passkit.webauthn.verifier import (
    AssertionResult,
    RegistrationResult,
    verify_assertion,
    verify_registration,
)

__all__ = [
    "verify_registration",
    "verify_assertion",
    "RegistrationResult",
    "AssertionResult",
    "parse_authenticator_data",
    "AuthenticatorData",
    "AttestedCredentialData",
    "parse_client_data",
    "ClientData",
]
