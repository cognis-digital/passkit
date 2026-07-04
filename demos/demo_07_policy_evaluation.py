"""Demo 7: declarative policy evaluation for a high-assurance tier.

Loads a YAML/JSON policy (AAL3-like, phishing-resistant, hardware-backed,
origin + authenticator allow-list) and evaluates two events against it.
"""

from passkit.policy import evaluate_policy, load_policy
from passkit.zerotrust import SignalInput, score_event

POLICY_YAML = """
name: fedgov-aal3
require_phishing_resistant: true
require_user_verification: true
require_hardware_backed: true
allowed_origins:
  - https://login.example.mil
allowed_aaguids:
  - ee882879721c491397753dfcce97072a
min_assurance: 85
min_aal: 3
"""


def main() -> int:
    policy = load_policy(POLICY_YAML)
    print(f"Loaded policy: {policy.name} (min AAL{policy.min_aal}, "
          f"min assurance {policy.min_assurance})\n")

    # Compliant event: hardware YubiKey, UV, origin match.
    good_score = score_event(SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=True, sign_count_observed=True, freshness_seconds=2,
    ))
    good = evaluate_policy(
        policy, phishing_resistant=True, user_verified=True,
        origin="https://login.example.mil",
        aaguid="ee882879721c491397753dfcce97072a",
        hardware_backed=True, assurance=good_score,
    )
    print(f"[compliant] allow={good.allow}")
    for m in good.matched:
        print(f"           + {m}")

    # Non-compliant: software passkey, wrong authenticator.
    bad_score = score_event(SignalInput(
        user_present=True, user_verified=True, hardware_backed=False,
        phishing_resistant=True, freshness_seconds=5,
    ))
    bad = evaluate_policy(
        policy, phishing_resistant=True, user_verified=True,
        origin="https://login.example.mil",
        aaguid="abababababababababababababababab",
        hardware_backed=False, assurance=bad_score,
    )
    print(f"\n[non-compliant] allow={bad.allow}")
    for r in bad.reasons:
        print(f"               - {r}")

    assert good.allow and not bad.allow
    print("\n[demo 7] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
