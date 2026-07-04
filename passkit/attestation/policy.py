"""Attestation policy checks: allowed authenticators, UV, resident key."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from passkit.attestation.metadata import normalize_aaguid
from passkit.attestation.parser import AttestationObject


@dataclass
class AttestationPolicy:
    allowed_aaguids: Optional[Sequence[str]] = None  # None = any
    denied_aaguids: Sequence[str] = field(default_factory=list)
    require_user_verification: bool = False
    require_resident_key: bool = False  # requires BE flag as a proxy signal
    allowed_formats: Optional[Sequence[str]] = None


@dataclass
class AttestationPolicyResult:
    allowed: bool
    reasons: List[str] = field(default_factory=list)


def check_attestation_policy(
    obj: AttestationObject, policy: AttestationPolicy
) -> AttestationPolicyResult:
    """Evaluate an attestation object against a policy. Returns allow/deny."""
    reasons: List[str] = []
    allowed = True

    aaguid = obj.aaguid_hex

    if policy.allowed_formats is not None and obj.fmt not in policy.allowed_formats:
        allowed = False
        reasons.append(
            f"attestation format {obj.fmt!r} not in allowed formats "
            f"{list(policy.allowed_formats)!r}"
        )

    if aaguid is not None:
        denied = {normalize_aaguid(a) for a in policy.denied_aaguids}
        if aaguid in denied:
            allowed = False
            reasons.append(f"AAGUID {aaguid} is explicitly denied")
        if policy.allowed_aaguids is not None:
            allowed_set = {normalize_aaguid(a) for a in policy.allowed_aaguids}
            if aaguid not in allowed_set:
                allowed = False
                reasons.append(
                    f"AAGUID {aaguid} not in allowed authenticators"
                )
    elif policy.allowed_aaguids is not None:
        allowed = False
        reasons.append("no AAGUID present but an allow-list is enforced")

    if policy.require_user_verification and not obj.auth_data.user_verified:
        allowed = False
        reasons.append("policy requires user verification but UV flag is not set")

    if policy.require_resident_key and not obj.auth_data.backup_eligible:
        # BE is not a perfect RK signal, but for discoverable passkeys it is
        # the best in-band hint available at registration.
        reasons.append(
            "resident key required; BE flag absent (cannot confirm discoverable "
            "credential from authenticatorData alone)"
        )

    if allowed and not reasons:
        reasons.append("attestation satisfies policy")
    return AttestationPolicyResult(allowed=allowed, reasons=reasons)


__all__ = [
    "AttestationPolicy",
    "AttestationPolicyResult",
    "check_attestation_policy",
]
