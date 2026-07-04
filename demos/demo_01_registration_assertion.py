"""Demo 1: end-to-end registration then assertion (ES256).

Shows the full happy path a relying party runs: issue a challenge, verify the
registration ceremony, persist the credential, then later verify a login
assertion against it.
"""

import os

from passkit import testing as T
from passkit.challenge import ChallengeStore
from passkit.webauthn import verify_assertion, verify_registration

RP = "login.example.mil"
ORIGIN = "https://login.example.mil"


def main() -> int:
    store = ChallengeStore()

    # --- Registration ---
    reg_challenge = store.issue()
    cred, att_obj, client_data = T.build_registration(
        RP, ORIGIN, reg_challenge.value
    )
    consumed = store.consume(reg_challenge.id)  # single-use
    reg = verify_registration(
        attestation_object=att_obj,
        client_data_json=client_data,
        expected_challenge=consumed.value,
        expected_origins=[ORIGIN],
        rp_id=RP,
        require_user_verification=True,
    )
    print(f"[registration] credential {reg.credential_id_b64[:16]}... registered")
    print(f"[registration] UV={reg.user_verified} count={reg.sign_count}")
    stored_public_key = reg.credential_public_key
    stored_count = reg.sign_count

    # --- Assertion (login) ---
    login_challenge = store.issue()
    ad, cd, sig = T.build_assertion(
        cred, RP, ORIGIN, login_challenge.value, sign_count=stored_count + 1
    )
    lc = store.consume(login_challenge.id)
    result = verify_assertion(
        credential_public_key=stored_public_key,
        authenticator_data=ad,
        client_data_json=cd,
        signature=sig,
        expected_challenge=lc.value,
        expected_origins=[ORIGIN],
        rp_id=RP,
        stored_sign_count=stored_count,
        require_user_verification=True,
    )
    print(f"[assertion] verified: new signCount={result.new_sign_count}, "
          f"clone_warning={result.clone_warning}")
    assert result.new_sign_count == stored_count + 1
    print("[demo 1] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
