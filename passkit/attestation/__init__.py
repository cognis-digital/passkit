"""Attestation statement parsing, evaluation, metadata, and policy."""

from passkit.attestation.metadata import (
    AuthenticatorInfo,
    known_aaguids,
    lookup,
    normalize_aaguid,
)
from passkit.attestation.parser import (
    AttestationEvaluation,
    AttestationObject,
    evaluate_attestation,
    parse_attestation_object,
)
from passkit.attestation.policy import (
    AttestationPolicy,
    AttestationPolicyResult,
    check_attestation_policy,
)

__all__ = [
    "parse_attestation_object",
    "evaluate_attestation",
    "AttestationObject",
    "AttestationEvaluation",
    "AttestationPolicy",
    "AttestationPolicyResult",
    "check_attestation_policy",
    "lookup",
    "normalize_aaguid",
    "known_aaguids",
    "AuthenticatorInfo",
]
