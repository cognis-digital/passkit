"""Device/session posture scorer.

Turns the discrete signals of a WebAuthn authentication event into a 0-100
assurance score and an AAL-style level loosely modeled on NIST SP 800-63B
Authenticator Assurance Levels. The mapping is explainable: every point is
attributable to a named signal so an operator can see *why* a session scored
what it did.

This is a risk-scoring aid, not a certification. The AAL label is "AAL2-like"
etc. because real 800-63 conformance also depends on process controls outside
an authentication event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class AAL(Enum):
    AAL1 = 1  # single-factor, phishable-resistant not required
    AAL2 = 2  # phishing-resistant MFA, user verification
    AAL3 = 3  # hardware-backed, verifier-impersonation resistant

    @property
    def label(self) -> str:
        return {1: "AAL1-like", 2: "AAL2-like", 3: "AAL3-like"}[self.value]


@dataclass
class SignalInput:
    """The observable facts about an authentication event."""

    user_present: bool = False
    user_verified: bool = False
    hardware_backed: Optional[bool] = None  # from AAGUID metadata; None=unknown
    phishing_resistant: bool = False  # origin+challenge bound assertion verified
    sign_count_ok: bool = True  # monotonic (no clone warning)
    sign_count_observed: bool = False  # authenticator emits a nonzero counter
    freshness_seconds: Optional[float] = None  # age of the challenge when used
    max_freshness_seconds: float = 300.0
    attestation_type: Optional[str] = None  # none|self|basic|unsupported
    aaguid_known: bool = False
    backup_eligible: Optional[bool] = None  # multi-device (synced) passkey hint


@dataclass
class ScoreSignal:
    name: str
    points: int
    max_points: int
    detail: str


@dataclass
class AssuranceScore:
    score: int
    level: AAL
    signals: List[ScoreSignal] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)

    def breakdown(self) -> str:
        lines = [f"Assurance score: {self.score}/100 ({self.level.label})"]
        for s in self.signals:
            lines.append(f"  [{s.points:+d}/{s.max_points}] {s.name}: {s.detail}")
        for c in self.caveats:
            lines.append(f"  ! {c}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level.label,
            "level_value": self.level.value,
            "signals": [
                {
                    "name": s.name,
                    "points": s.points,
                    "max_points": s.max_points,
                    "detail": s.detail,
                }
                for s in self.signals
            ],
            "caveats": list(self.caveats),
        }


def score_event(sig: SignalInput) -> AssuranceScore:
    """Compute an explainable assurance score from event signals."""
    signals: List[ScoreSignal] = []
    caveats: List[str] = []

    # 1. User present (weakest, table-stakes): 10
    up = 10 if sig.user_present else 0
    signals.append(
        ScoreSignal("user_present", up, 10,
                    "UP flag set" if sig.user_present else "UP flag NOT set")
    )

    # 2. Phishing resistance (origin + challenge bound, sig verified): 30
    pr = 30 if sig.phishing_resistant else 0
    signals.append(
        ScoreSignal(
            "phishing_resistant", pr, 30,
            "assertion bound to origin+challenge and signature verified"
            if sig.phishing_resistant
            else "not established as phishing-resistant",
        )
    )
    if not sig.phishing_resistant:
        caveats.append("event is not phishing-resistant; cap at AAL1-like")

    # 3. User verification (biometric/PIN gesture): 20
    uv = 20 if sig.user_verified else 0
    signals.append(
        ScoreSignal("user_verified", uv, 20,
                    "UV flag set (PIN/biometric)" if sig.user_verified else "UV flag NOT set")
    )

    # 4. Hardware-backed key: 20
    if sig.hardware_backed is True:
        hw = 20
        detail = "credential is hardware-backed (per AAGUID metadata)"
    elif sig.hardware_backed is False:
        hw = 0
        detail = "credential is software-backed"
    else:
        hw = 5
        detail = "hardware backing unknown (partial credit)"
        caveats.append("hardware backing unknown; supply AAGUID metadata to confirm")
    signals.append(ScoreSignal("hardware_backed", hw, 20, detail))

    # 5. Anti-clone / signCount: 10
    if not sig.sign_count_ok:
        sc = -10
        detail = "signCount regressed: possible cloned authenticator"
        caveats.append("clone warning: signCount did not advance")
    elif sig.sign_count_observed:
        sc = 10
        detail = "signCount advanced monotonically"
    else:
        sc = 5
        detail = "authenticator does not emit signCount (0); no clone signal"
    signals.append(ScoreSignal("sign_count", sc, 10, detail))

    # 6. Freshness: 10
    if sig.freshness_seconds is None:
        fr = 5
        detail = "challenge age unknown (partial credit)"
    elif sig.freshness_seconds < 0:
        fr = 0
        detail = "negative challenge age (clock/replay anomaly)"
        caveats.append("negative freshness: check clocks / replay")
    elif sig.freshness_seconds <= sig.max_freshness_seconds:
        # linear: full points when instant, fading to ~2 at the TTL edge
        ratio = 1.0 - (sig.freshness_seconds / max(sig.max_freshness_seconds, 1e-9))
        fr = max(2, round(10 * ratio))
        detail = f"challenge consumed {sig.freshness_seconds:.0f}s after issue"
    else:
        fr = 0
        detail = f"challenge stale ({sig.freshness_seconds:.0f}s > TTL)"
        caveats.append("challenge exceeded TTL")
    signals.append(ScoreSignal("freshness", fr, 10, detail))

    total = up + pr + uv + hw + sc + fr
    total = max(0, min(100, total))

    level = _classify(sig, total)
    return AssuranceScore(score=total, level=level, signals=signals, caveats=caveats)


def _classify(sig: SignalInput, score: int) -> AAL:
    """Map signals+score to an AAL-like level.

    AAL3-like: phishing-resistant + hardware-backed + user verification.
    AAL2-like: phishing-resistant + user verification.
    else AAL1-like.
    """
    if (
        sig.phishing_resistant
        and sig.hardware_backed is True
        and sig.user_verified
        and sig.sign_count_ok
        and score >= 85
    ):
        return AAL.AAL3
    if sig.phishing_resistant and sig.user_verified and score >= 60:
        return AAL.AAL2
    return AAL.AAL1


__all__ = [
    "score_event",
    "AssuranceScore",
    "ScoreSignal",
    "SignalInput",
    "AAL",
]
