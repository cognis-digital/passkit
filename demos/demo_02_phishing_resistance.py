"""Demo 2: phishing resistance via origin binding.

An attacker stands up a lookalike domain (login.examp1e.mil with a digit '1')
and relays a real user's WebAuthn ceremony to the legitimate server. Because
the browser signs the *actual* origin it ran on, the verifier's origin-binding
check rejects the relayed assertion. This is the property Nimbus-Key markets;
here it is open, inspectable, and test-covered.
"""

import os

from passkit import testing as T
from passkit.errors import VerificationError
from passkit.webauthn import verify_assertion, verify_registration

RP = "login.example.mil"
GOOD_ORIGIN = "https://login.example.mil"
PHISH_ORIGIN = "https://login.examp1e.mil"  # lookalike (digit 1)


def main() -> int:
    challenge = os.urandom(32)
    cred, att, cd = T.build_registration(RP, GOOD_ORIGIN, challenge)
    reg = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=challenge, expected_origins=[GOOD_ORIGIN], rp_id=RP,
    )
    print("[setup] credential registered at", GOOD_ORIGIN)

    login_challenge = os.urandom(32)
    # The victim's authenticator signs the phishing origin the browser saw.
    ad, cd2, sig = T.build_assertion(cred, RP, PHISH_ORIGIN, login_challenge)

    try:
        verify_assertion(
            credential_public_key=reg.credential_public_key,
            authenticator_data=ad, client_data_json=cd2, signature=sig,
            expected_challenge=login_challenge, expected_origins=[GOOD_ORIGIN],
            rp_id=RP,
        )
        print("[demo 2] FAIL: phishing ceremony was accepted!")
        return 1
    except VerificationError as exc:
        print(f"[defense] relayed ceremony REJECTED: code={exc.code}")
        print(f"[defense] {exc}")

    print("[demo 2] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
