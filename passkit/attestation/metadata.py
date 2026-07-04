"""A small, offline AAGUID -> authenticator metadata lookup.

This is intentionally a tiny, curated, offline table (not the full FIDO MDS)
so passkit stays air-gap friendly. Callers who need the authoritative MDS can
supply their own table to ``lookup`` via the ``extra`` argument. Values are
descriptive only; trust decisions belong in policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

ZERO_AAGUID = "00000000000000000000000000000000"


@dataclass
class AuthenticatorInfo:
    name: str
    hardware_backed: bool
    user_verification: bool  # capable of UV
    notes: str = ""


# AAGUIDs are 16-byte identifiers rendered as 32 lowercase hex chars here.
_KNOWN: Dict[str, AuthenticatorInfo] = {
    ZERO_AAGUID: AuthenticatorInfo(
        name="Unknown / privacy (all-zero AAGUID)",
        hardware_backed=False,
        user_verification=False,
        notes="Reported by platform authenticators that withhold AAGUID.",
    ),
    "ee882879721c491397753dfcce97072a": AuthenticatorInfo(
        name="YubiKey 5 Series",
        hardware_backed=True,
        user_verification=True,
    ),
    "fa2b99dc9e3942578f924a30d23c4118": AuthenticatorInfo(
        name="YubiKey 5 Series (FIPS)",
        hardware_backed=True,
        user_verification=True,
        notes="FIPS 140 validated variant.",
    ),
    "08987058cadc4b81b6e130de50dcbe96": AuthenticatorInfo(
        name="Windows Hello (hardware)",
        hardware_backed=True,
        user_verification=True,
    ),
    "9ddd1817af5a4672a2b93e3dd95000a9": AuthenticatorInfo(
        name="Windows Hello (software)",
        hardware_backed=False,
        user_verification=True,
    ),
    "adce000235bcc60a648b0b25f1f05503": AuthenticatorInfo(
        name="Chrome on Mac (Touch ID platform)",
        hardware_backed=True,
        user_verification=True,
    ),
}


def normalize_aaguid(aaguid) -> str:
    """Return a 32-char lowercase hex AAGUID from bytes or hex string."""
    if isinstance(aaguid, (bytes, bytearray)):
        return bytes(aaguid).hex()
    return str(aaguid).replace("-", "").lower()


def lookup(
    aaguid, extra: Optional[Dict[str, AuthenticatorInfo]] = None
) -> Optional[AuthenticatorInfo]:
    """Look up authenticator metadata by AAGUID (bytes or hex)."""
    key = normalize_aaguid(aaguid)
    if extra and key in extra:
        return extra[key]
    return _KNOWN.get(key)


def known_aaguids() -> Dict[str, AuthenticatorInfo]:
    """Return a copy of the built-in table."""
    return dict(_KNOWN)


__all__ = [
    "AuthenticatorInfo",
    "lookup",
    "normalize_aaguid",
    "known_aaguids",
    "ZERO_AAGUID",
]
