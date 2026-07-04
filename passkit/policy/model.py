"""Policy data model and decision types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence


@dataclass
class Policy:
    """A declarative authentication policy.

    Fields default to permissive-but-safe. A missing constraint means
    "unconstrained"; an explicit list means "must be in this list".
    """

    name: str = "default"
    require_phishing_resistant: bool = True
    require_user_verification: bool = False
    allowed_origins: Optional[Sequence[str]] = None
    allowed_aaguids: Optional[Sequence[str]] = None
    denied_aaguids: Sequence[str] = field(default_factory=list)
    allowed_formats: Optional[Sequence[str]] = None
    min_assurance: int = 0
    min_aal: int = 1  # 1..3
    require_hardware_backed: bool = False

    @staticmethod
    def from_dict(d: dict) -> "Policy":
        known = {
            "name",
            "require_phishing_resistant",
            "require_user_verification",
            "allowed_origins",
            "allowed_aaguids",
            "denied_aaguids",
            "allowed_formats",
            "min_assurance",
            "min_aal",
            "require_hardware_backed",
        }
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown policy fields: {sorted(unknown)}")
        p = Policy(**{k: d[k] for k in d if k in known})
        if not (1 <= p.min_aal <= 3):
            raise ValueError("min_aal must be between 1 and 3")
        if not (0 <= p.min_assurance <= 100):
            raise ValueError("min_assurance must be between 0 and 100")
        return p


@dataclass
class PolicyDecision:
    allow: bool
    policy_name: str
    reasons: List[str] = field(default_factory=list)
    matched: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "allow": self.allow,
            "policy": self.policy_name,
            "reasons": list(self.reasons),
            "matched": list(self.matched),
        }


__all__ = ["Policy", "PolicyDecision"]
