"""Attestation object parsing (packed / none formats).

The attestation object is a CBOR map:
    {
      "fmt":     <text>            e.g. "packed", "none", "fido-u2f", ...
      "attStmt": <map>             format-specific statement
      "authData": <bytes>          the authenticatorData
    }

We fully parse ``none`` and ``packed`` (the two the task targets). For other
formats we still surface fmt + authData so higher layers can decide, but mark
the statement as unverified rather than pretending we validated it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from passkit._cbor import loads as cbor_loads
from passkit.errors import AttestationError
from passkit.webauthn.authdata import AuthenticatorData, parse_authenticator_data

# Subset of the FIDO alliance / Metadata Service style algorithm identifiers.
COSE_ALG_ES256 = -7
COSE_ALG_RS256 = -257


@dataclass
class AttestationObject:
    fmt: str
    att_stmt: Dict[Any, Any]
    auth_data: AuthenticatorData
    raw: bytes

    @property
    def aaguid(self) -> Optional[bytes]:
        if self.auth_data.attested_credential_data:
            return self.auth_data.attested_credential_data.aaguid
        return None

    @property
    def aaguid_hex(self) -> Optional[str]:
        aaguid = self.aaguid
        return aaguid.hex() if aaguid is not None else None


@dataclass
class AttestationEvaluation:
    fmt: str
    aaguid: Optional[str]
    attestation_type: str  # "none" | "self" | "basic" | "unsupported"
    signature_present: bool
    x5c_present: bool
    algorithm: Optional[int]
    trust_path_length: int
    notes: list = field(default_factory=list)


def parse_attestation_object(data: bytes) -> AttestationObject:
    """Parse an attestation object into structured form."""
    try:
        obj = cbor_loads(data)
    except ValueError as exc:
        raise AttestationError(
            f"attestation object is not valid CBOR: {exc}", "bad_cbor"
        ) from exc
    if not isinstance(obj, dict):
        raise AttestationError("attestation object is not a map", "bad_structure")

    fmt = obj.get("fmt")
    att_stmt = obj.get("attStmt")
    auth_data_bytes = obj.get("authData")
    if not isinstance(fmt, str):
        raise AttestationError("attestation object missing fmt", "bad_structure")
    if not isinstance(att_stmt, dict):
        raise AttestationError("attestation object missing attStmt", "bad_structure")
    if not isinstance(auth_data_bytes, (bytes, bytearray)):
        raise AttestationError("attestation object missing authData", "bad_structure")

    auth_data = parse_authenticator_data(bytes(auth_data_bytes))
    return AttestationObject(
        fmt=fmt,
        att_stmt=att_stmt,
        auth_data=auth_data,
        raw=bytes(data),
    )


def evaluate_attestation(obj: AttestationObject) -> AttestationEvaluation:
    """Classify the attestation statement without asserting external trust.

    Determines the attestation *type* (none / self / basic) from the statement
    shape. We deliberately do not chase x5c to a root here — that requires an
    out-of-band trust store (e.g. FIDO MDS) which callers supply via policy.
    """
    aaguid = obj.aaguid_hex
    notes: list = []

    if obj.fmt == "none":
        if obj.att_stmt:
            notes.append("fmt=none but attStmt is non-empty")
        return AttestationEvaluation(
            fmt="none",
            aaguid=aaguid,
            attestation_type="none",
            signature_present=False,
            x5c_present=False,
            algorithm=None,
            trust_path_length=0,
            notes=notes,
        )

    if obj.fmt == "packed":
        alg = obj.att_stmt.get("alg")
        sig = obj.att_stmt.get("sig")
        x5c = obj.att_stmt.get("x5c")
        sig_present = isinstance(sig, (bytes, bytearray))
        x5c_present = isinstance(x5c, list) and len(x5c) > 0
        if not sig_present:
            notes.append("packed attStmt missing sig")
        if alg not in (COSE_ALG_ES256, COSE_ALG_RS256):
            notes.append(f"packed attStmt uses uncommon alg {alg}")
        att_type = "basic" if x5c_present else "self"
        return AttestationEvaluation(
            fmt="packed",
            aaguid=aaguid,
            attestation_type=att_type,
            signature_present=sig_present,
            x5c_present=x5c_present,
            algorithm=alg if isinstance(alg, int) else None,
            trust_path_length=len(x5c) if x5c_present else 0,
            notes=notes,
        )

    notes.append(f"attestation format {obj.fmt!r} is not evaluated by passkit")
    return AttestationEvaluation(
        fmt=obj.fmt,
        aaguid=aaguid,
        attestation_type="unsupported",
        signature_present="sig" in obj.att_stmt,
        x5c_present="x5c" in obj.att_stmt,
        algorithm=obj.att_stmt.get("alg") if isinstance(obj.att_stmt.get("alg"), int) else None,
        trust_path_length=0,
        notes=notes,
    )


__all__ = [
    "AttestationObject",
    "AttestationEvaluation",
    "parse_attestation_object",
    "evaluate_attestation",
]
