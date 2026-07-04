"""Policy loading (yaml/json) and evaluation against an auth event."""

from __future__ import annotations

import json
from typing import List, Optional

from passkit._util import normalize_origin
from passkit.attestation.metadata import normalize_aaguid
from passkit.errors import PolicyError
from passkit.policy.model import Policy, PolicyDecision
from passkit.zerotrust.scorer import AssuranceScore


def load_policy(text: str, fmt: Optional[str] = None) -> Policy:
    """Load a Policy from YAML or JSON text.

    YAML is parsed if PyYAML is available; otherwise JSON is required. ``fmt``
    may be "yaml" or "json" to force a parser.
    """
    fmt = (fmt or "").lower()
    if fmt == "json" or (not fmt and text.lstrip().startswith("{")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"invalid JSON policy: {exc}") from exc
    else:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            if fmt == "yaml":
                raise PolicyError(
                    "PyYAML not installed; provide JSON or install pyyaml"
                ) from exc
            # last-ditch: try JSON (YAML is a superset for our simple docs)
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                raise PolicyError(
                    "cannot parse policy: install pyyaml or provide JSON"
                ) from exc
        else:
            data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise PolicyError("policy document must be a mapping/object")
    try:
        return Policy.from_dict(data)
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc


def evaluate_policy(
    policy: Policy,
    *,
    phishing_resistant: bool = False,
    user_verified: bool = False,
    origin: Optional[str] = None,
    aaguid: Optional[str] = None,
    attestation_format: Optional[str] = None,
    hardware_backed: Optional[bool] = None,
    assurance: Optional[AssuranceScore] = None,
) -> PolicyDecision:
    """Evaluate an auth event's facts against a policy. Returns allow/deny."""
    reasons: List[str] = []
    matched: List[str] = []
    allow = True

    if policy.require_phishing_resistant:
        if phishing_resistant:
            matched.append("phishing-resistant factor present")
        else:
            allow = False
            reasons.append("policy requires a phishing-resistant factor")

    if policy.require_user_verification:
        if user_verified:
            matched.append("user verification present")
        else:
            allow = False
            reasons.append("policy requires user verification")

    if policy.require_hardware_backed:
        if hardware_backed is True:
            matched.append("hardware-backed credential")
        else:
            allow = False
            reasons.append(
                "policy requires a hardware-backed credential "
                f"(observed: {hardware_backed})"
            )

    if policy.allowed_origins is not None:
        if origin is None:
            allow = False
            reasons.append("policy constrains origins but none was provided")
        else:
            try:
                got = normalize_origin(origin)
                allowed = {normalize_origin(o) for o in policy.allowed_origins}
            except ValueError as exc:
                allow = False
                reasons.append(f"invalid origin in policy or event: {exc}")
            else:
                if got in allowed:
                    matched.append(f"origin {got} allowed")
                else:
                    allow = False
                    reasons.append(f"origin {got} not in allowed origins")

    if aaguid is not None:
        norm = normalize_aaguid(aaguid)
        if norm in {normalize_aaguid(a) for a in policy.denied_aaguids}:
            allow = False
            reasons.append(f"AAGUID {norm} is denied")
        if policy.allowed_aaguids is not None:
            if norm in {normalize_aaguid(a) for a in policy.allowed_aaguids}:
                matched.append(f"AAGUID {norm} allowed")
            else:
                allow = False
                reasons.append(f"AAGUID {norm} not in allowed authenticators")
    elif policy.allowed_aaguids is not None:
        allow = False
        reasons.append("policy has an AAGUID allow-list but event has no AAGUID")

    if policy.allowed_formats is not None and attestation_format is not None:
        if attestation_format in policy.allowed_formats:
            matched.append(f"attestation format {attestation_format} allowed")
        else:
            allow = False
            reasons.append(
                f"attestation format {attestation_format} not allowed"
            )

    if assurance is not None:
        if assurance.score >= policy.min_assurance:
            matched.append(
                f"assurance {assurance.score} >= min {policy.min_assurance}"
            )
        else:
            allow = False
            reasons.append(
                f"assurance {assurance.score} below minimum {policy.min_assurance}"
            )
        if assurance.level.value >= policy.min_aal:
            matched.append(
                f"level {assurance.level.label} >= min AAL{policy.min_aal}"
            )
        else:
            allow = False
            reasons.append(
                f"level {assurance.level.label} below minimum AAL{policy.min_aal}"
            )
    elif policy.min_assurance > 0 or policy.min_aal > 1:
        allow = False
        reasons.append(
            "policy sets assurance/AAL minimums but no assurance score provided"
        )

    if allow and not reasons:
        reasons.append("all policy constraints satisfied")
    return PolicyDecision(
        allow=allow, policy_name=policy.name, reasons=reasons, matched=matched
    )


__all__ = ["load_policy", "evaluate_policy"]
