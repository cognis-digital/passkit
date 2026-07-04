"""Demo 6: zero-trust assurance scoring across authenticator profiles.

The same login event scores differently depending on the authenticator and
context. Each score is explainable: every point traces to a named signal, and
the AAL-like level follows NIST SP 800-63B intent.
"""

from passkit.zerotrust import SignalInput, score_event

PROFILES = {
    "hardware security key (UV, hardware-backed, fresh)": SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=True, sign_count_observed=True, freshness_seconds=2,
    ),
    "synced passkey (software, UV, fresh)": SignalInput(
        user_present=True, user_verified=True, hardware_backed=False,
        phishing_resistant=True, sign_count_observed=False, freshness_seconds=8,
        backup_eligible=True,
    ),
    "usb key, no user verification": SignalInput(
        user_present=True, user_verified=False, hardware_backed=True,
        phishing_resistant=True, sign_count_observed=True, freshness_seconds=3,
    ),
    "suspected clone (counter regressed)": SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=True, sign_count_ok=False, freshness_seconds=1,
    ),
    "non-phishing-resistant factor": SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=False,
    ),
}


def main() -> int:
    for label, sig in PROFILES.items():
        score = score_event(sig)
        print(f"=== {label} ===")
        print(score.breakdown())
        print()
    # sanity: hardware key should outscore non-phishing-resistant
    hw = score_event(PROFILES["hardware security key (UV, hardware-backed, fresh)"])
    weak = score_event(PROFILES["non-phishing-resistant factor"])
    assert hw.score > weak.score
    assert hw.level.value >= 3
    print("[demo 6] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
