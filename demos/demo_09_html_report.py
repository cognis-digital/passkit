"""Demo 9: render a self-contained HTML assurance report.

Produces a standalone HTML file summarizing an authentication event's
assurance breakdown and the policy decision — handy for audit trails and
incident review.
"""

import os

from passkit.policy import evaluate_policy, load_policy
from passkit.report import render_report
from passkit.zerotrust import SignalInput, score_event


def main() -> int:
    score = score_event(SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=True, sign_count_observed=True, freshness_seconds=3,
    ))
    policy = load_policy('{"name":"fedgov-aal3","min_aal":3,"min_assurance":85}')
    decision = evaluate_policy(
        policy, phishing_resistant=True, user_verified=True, assurance=score
    )

    html = render_report(
        score,
        subject="CAC-backed WebAuthn login",
        rp_id="login.example.mil",
        origin="https://login.example.mil",
        decision=decision,
    )
    out = os.path.join(os.path.dirname(__file__), "assurance_report.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"[report] wrote {len(html)} bytes to {os.path.basename(out)}")
    print(f"[report] score={score.score} level={score.level.label} "
          f"decision={'ALLOW' if decision.allow else 'DENY'}")
    assert "<!doctype html>" in html
    assert score.level.label in html
    print("[demo 9] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
