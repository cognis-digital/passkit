"""Exception hierarchy for passkit."""


class PassKitError(Exception):
    """Base class for all passkit errors."""


class VerificationError(PassKitError):
    """Raised when a WebAuthn registration or assertion fails verification.

    Carries a machine-readable ``code`` so callers can branch on the specific
    failure (e.g. reject a relayed assertion differently from a bad signature).
    """

    def __init__(self, message: str, code: str = "verification_error"):
        super().__init__(message)
        self.code = code


class PolicyError(PassKitError):
    """Raised when a policy document is malformed."""


class ChallengeError(PassKitError):
    """Raised for replay / expiry / unknown-nonce conditions."""

    def __init__(self, message: str, code: str = "challenge_error"):
        super().__init__(message)
        self.code = code


class AttestationError(PassKitError):
    """Raised when an attestation statement cannot be parsed or fails policy."""

    def __init__(self, message: str, code: str = "attestation_error"):
        super().__init__(message)
        self.code = code
