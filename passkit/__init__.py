"""passkit - open, self-hostable, standards-based phishing-resistant authentication tooling.

A verifier-side WebAuthn/FIDO2 toolkit built for correctness:
real signature verification, real replay/clone protection, and real origin
binding (the property that makes WebAuthn phishing-resistant).

Modules:
    webauthn     WebAuthn/FIDO2 registration + assertion verifiers
    attestation  Attestation statement parsing + policy evaluation
    zerotrust    Device/session posture scoring (NIST 800-63 AAL-style)
    challenge    Single-use nonce store + cross-device challenge builders
    policy       Declarative auth policy evaluation
"""

__version__ = "1.0.0"

from passkit.webauthn import (  # noqa: E402
    verify_registration,
    verify_assertion,
    RegistrationResult,
    AssertionResult,
)
from passkit.zerotrust import score_event, AssuranceScore  # noqa: E402
from passkit.challenge import ChallengeStore, build_challenge  # noqa: E402
from passkit.policy import Policy, evaluate_policy, PolicyDecision  # noqa: E402
from passkit.errors import PassKitError, VerificationError, PolicyError  # noqa: E402

__all__ = [
    "__version__",
    "verify_registration",
    "verify_assertion",
    "RegistrationResult",
    "AssertionResult",
    "score_event",
    "AssuranceScore",
    "ChallengeStore",
    "build_challenge",
    "Policy",
    "evaluate_policy",
    "PolicyDecision",
    "PassKitError",
    "VerificationError",
    "PolicyError",
]
