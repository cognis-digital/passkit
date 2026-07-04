"""Demo 5: attestation parsing + authenticator allow-list policy.

A regulated deployment (defense/banking) may only accept specific certified
authenticators. This parses a packed attestation, surfaces the AAGUID and
device metadata, and enforces an allow-list + user-verification policy.
"""

import os

from passkit import testing as T
from passkit.attestation import (
    AttestationPolicy,
    check_attestation_policy,
    evaluate_attestation,
    lookup,
    parse_attestation_object,
)

RP = "login.example.mil"
ORIGIN = "https://login.example.mil"
YUBIKEY_5 = "ee882879721c491397753dfcce97072a"
UNKNOWN = "abababababababababababababababab"


def inspect(aaguid_hex: str, label: str, policy: AttestationPolicy) -> bool:
    _, att, _ = T.build_registration(
        RP, ORIGIN, os.urandom(32), fmt="packed", aaguid=bytes.fromhex(aaguid_hex)
    )
    obj = parse_attestation_object(att)
    ev = evaluate_attestation(obj)
    info = lookup(obj.aaguid_hex)
    name = info.name if info else "unknown authenticator"
    print(f"[{label}] fmt={ev.fmt} type={ev.attestation_type} aaguid={obj.aaguid_hex}")
    print(f"[{label}] device: {name}")
    result = check_attestation_policy(obj, policy)
    print(f"[{label}] policy allow={result.allowed}: {result.reasons[0]}")
    return result.allowed


def main() -> int:
    policy = AttestationPolicy(
        allowed_aaguids=[YUBIKEY_5],
        require_user_verification=True,
        allowed_formats=["packed"],
    )
    print("Policy: only YubiKey 5, packed attestation, UV required\n")

    ok = inspect(YUBIKEY_5, "yubikey", policy)
    print()
    denied = inspect(UNKNOWN, "unknown", policy)

    assert ok and not denied
    print("\n[demo 5] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
