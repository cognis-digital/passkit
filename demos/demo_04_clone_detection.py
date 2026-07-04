"""Demo 4: cloned-authenticator detection via signCount.

A cloned hardware token replays a stale signature counter. The verifier's
monotonicity check flags the anomaly (WebAuthn 7.2 step 21) so the relying
party can step up or lock the account.
"""

import os

from passkit import testing as T
from passkit.webauthn import verify_assertion, verify_registration

RP = "bank.example.com"
ORIGIN = "https://bank.example.com"


def main() -> int:
    challenge = os.urandom(32)
    cred, att, cd = T.build_registration(RP, ORIGIN, challenge)
    reg = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=challenge, expected_origins=[ORIGIN], rp_id=RP,
    )

    # Legitimate login advances the counter.
    c1 = os.urandom(32)
    ad, cdj, sig = T.build_assertion(cred, RP, ORIGIN, c1, sign_count=10)
    r1 = verify_assertion(
        credential_public_key=reg.credential_public_key,
        authenticator_data=ad, client_data_json=cdj, signature=sig,
        expected_challenge=c1, expected_origins=[ORIGIN], rp_id=RP,
        stored_sign_count=9,
    )
    print(f"[login 1] OK, counter {r1.new_sign_count}, clone={r1.clone_warning}")

    # Cloned token presents a counter that did NOT advance.
    c2 = os.urandom(32)
    ad2, cdj2, sig2 = T.build_assertion(cred, RP, ORIGIN, c2, sign_count=10)
    r2 = verify_assertion(
        credential_public_key=reg.credential_public_key,
        authenticator_data=ad2, client_data_json=cdj2, signature=sig2,
        expected_challenge=c2, expected_origins=[ORIGIN], rp_id=RP,
        stored_sign_count=10,  # last seen was already 10
    )
    print(f"[login 2] signature valid but counter stale: clone={r2.clone_warning}")
    for w in r2.warnings:
        print(f"[defense] {w}")
    assert r2.clone_warning
    print("[demo 4] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
