"""Demo 10: tamper matrix — every mutation the verifier must reject.

Builds one valid assertion, then applies a battery of tampering/attack
mutations and confirms each is rejected with the expected error code. This is
the "prove it rejects bad input" companion to the happy-path demos.
"""

import os

from passkit import testing as T
from passkit.errors import VerificationError
from passkit.webauthn import verify_assertion, verify_registration

RP = "login.example.mil"
ORIGIN = "https://login.example.mil"


def main() -> int:
    reg_chal = os.urandom(32)
    cred, att, cd = T.build_registration(RP, ORIGIN, reg_chal)
    reg = verify_registration(
        attestation_object=att, client_data_json=cd,
        expected_challenge=reg_chal, expected_origins=[ORIGIN], rp_id=RP,
    )
    pk = reg.credential_public_key
    chal = os.urandom(32)
    ad, cdj, sig = T.build_assertion(cred, RP, ORIGIN, chal, sign_count=5)

    base = dict(
        credential_public_key=pk, authenticator_data=ad, client_data_json=cdj,
        signature=sig, expected_challenge=chal, expected_origins=[ORIGIN], rp_id=RP,
    )

    # sanity: base is valid
    verify_assertion(**base, stored_sign_count=1)
    print("[base] valid assertion accepted")

    cases = []

    def expect_reject(name, expected_code, **overrides):
        kwargs = dict(base)
        kwargs.update(overrides)
        try:
            verify_assertion(**kwargs, stored_sign_count=1)
            cases.append((name, "ACCEPTED (BAD)", False))
        except VerificationError as exc:
            ok = exc.code == expected_code
            cases.append((name, exc.code, ok))

    expect_reject("wrong challenge (replay)", "challenge_mismatch",
                  expected_challenge=os.urandom(32))
    expect_reject("relayed origin (phishing)", "origin_mismatch",
                  expected_origins=["https://evil.example.mil"])
    expect_reject("wrong rp_id", "rpid_mismatch", rp_id="evil.mil")

    tampered_sig = bytearray(sig)
    tampered_sig[-1] ^= 0xFF
    expect_reject("tampered signature", "bad_signature", signature=bytes(tampered_sig))

    tampered_ad = bytearray(ad)
    tampered_ad[10] ^= 0xFF  # inside rpIdHash region
    expect_reject("tampered authData", "rpid_mismatch",
                  authenticator_data=bytes(tampered_ad))

    other = T.generate_credential()
    expect_reject("wrong public key", "bad_signature",
                  credential_public_key=other.cose_public_key)

    all_ok = True
    for name, code, ok in cases:
        status = "REJECTED" if ok else "!!! NOT PROPERLY REJECTED"
        print(f"[{status}] {name}: {code}")
        all_ok = all_ok and ok

    assert all_ok, "a tampering case was not rejected as expected"
    print("[demo 10] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
