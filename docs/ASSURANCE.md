# Assurance scoring & AAL mapping

`passkit.zerotrust.score_event` turns the observable facts of an authentication
event into a **0–100 assurance score** and an **AAL-like level**. Every point is
attributable to a named signal, so an operator can see *why* a session scored
what it did.

## Signals and weights

| Signal | Max | Meaning |
| ------ | --- | ------- |
| `user_present` | 10 | UP flag set (a human touched the authenticator). |
| `phishing_resistant` | 30 | The assertion was origin+challenge bound and its signature verified. This is the dominant factor. |
| `user_verified` | 20 | UV flag set (PIN/biometric gesture). |
| `hardware_backed` | 20 | Credential is hardware-backed per AAGUID metadata (5 pts partial if unknown). |
| `sign_count` | 10 | +10 monotonic advance, +5 no counter emitted, **−10** if regressed (clone). |
| `freshness` | 10 | How recently the challenge was consumed vs. its TTL (linear). |

Score is clamped to `[0, 100]`.

## Level mapping

The score plus the signal shape determines an AAL-like level (modeled on NIST
SP 800-63B):

- **AAL3-like** — `phishing_resistant` **and** `hardware_backed` **and**
  `user_verified` **and** no clone warning **and** score ≥ 85.
- **AAL2-like** — `phishing_resistant` **and** `user_verified` **and** score ≥ 60.
- **AAL1-like** — otherwise.

A non-phishing-resistant event is capped at AAL1-like regardless of other
signals, and a clone warning removes AAL3 eligibility.

## Caveats surfaced

The scorer attaches human-readable caveats, e.g.:

- "event is not phishing-resistant; cap at AAL1-like"
- "clone warning: signCount did not advance"
- "challenge exceeded TTL"
- "hardware backing unknown; supply AAGUID metadata to confirm"

## Example

```python
from passkit.zerotrust import SignalInput, score_event

score = score_event(SignalInput(
    user_present=True, user_verified=True, hardware_backed=True,
    phishing_resistant=True, sign_count_observed=True, freshness_seconds=2,
))
print(score.breakdown())
# Assurance score: 100/100 (AAL3-like)
#   [+10/10] user_present: UP flag set
#   [+30/30] phishing_resistant: ...
#   ...
```

## Feeding it from a verifier result

A typical mapping from `AssertionResult` + AAGUID metadata:

```python
from passkit.attestation import lookup
from passkit.zerotrust import SignalInput, score_event

info = lookup(aaguid_hex)  # may be None
sig = SignalInput(
    user_present=result.user_present,
    user_verified=result.user_verified,
    hardware_backed=(info.hardware_backed if info else None),
    phishing_resistant=True,               # verify_assertion enforced binding
    sign_count_ok=not result.clone_warning,
    sign_count_observed=result.new_sign_count > 0,
    freshness_seconds=age_of_challenge_seconds,
)
score = score_event(sig)
```

## Not a certification

The AAL labels use the "-like" suffix intentionally. Formal 800-63 conformance
depends on identity proofing, session management, and reauthentication policies
that live outside a single authentication event. Treat the score as a risk aid
for step-up and monitoring decisions.
