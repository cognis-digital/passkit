import pytest

from passkit.errors import PolicyError
from passkit.policy import Policy, evaluate_policy, load_policy
from passkit.zerotrust import SignalInput, score_event

ORIGIN = "https://login.example.mil"
YUBI = "ee882879721c491397753dfcce97072a"


def test_load_json_policy():
    p = load_policy('{"name":"gov","require_phishing_resistant":true,"min_aal":3}')
    assert p.name == "gov"
    assert p.min_aal == 3


def test_load_rejects_unknown_field():
    with pytest.raises(PolicyError):
        load_policy('{"nope": 1}')


def test_load_rejects_bad_aal():
    with pytest.raises(PolicyError):
        load_policy('{"min_aal": 9}')


def test_load_rejects_non_object():
    with pytest.raises(PolicyError):
        load_policy("[1,2,3]")


def test_allow_when_all_satisfied():
    p = Policy(require_phishing_resistant=True, allowed_origins=[ORIGIN])
    d = evaluate_policy(p, phishing_resistant=True, origin=ORIGIN)
    assert d.allow


def test_deny_missing_phishing_resistant():
    p = Policy(require_phishing_resistant=True)
    d = evaluate_policy(p, phishing_resistant=False)
    assert not d.allow
    assert any("phishing" in r for r in d.reasons)


def test_deny_wrong_origin():
    p = Policy(allowed_origins=[ORIGIN])
    d = evaluate_policy(p, phishing_resistant=True, origin="https://evil.mil")
    assert not d.allow


def test_deny_missing_uv():
    p = Policy(require_user_verification=True)
    d = evaluate_policy(p, phishing_resistant=True, user_verified=False)
    assert not d.allow


def test_deny_unlisted_aaguid():
    p = Policy(allowed_aaguids=[YUBI])
    d = evaluate_policy(p, phishing_resistant=True, aaguid="ab" * 16)
    assert not d.allow


def test_allow_listed_aaguid():
    p = Policy(allowed_aaguids=[YUBI])
    d = evaluate_policy(p, phishing_resistant=True, aaguid=YUBI)
    assert d.allow


def test_deny_denied_aaguid():
    p = Policy(denied_aaguids=[YUBI])
    d = evaluate_policy(p, phishing_resistant=True, aaguid=YUBI)
    assert not d.allow


def test_require_hardware_backed():
    p = Policy(require_hardware_backed=True)
    assert not evaluate_policy(p, phishing_resistant=True, hardware_backed=False).allow
    assert evaluate_policy(p, phishing_resistant=True, hardware_backed=True).allow


def test_min_assurance_and_aal_with_score():
    p = Policy(min_assurance=85, min_aal=3)
    sig = SignalInput(user_present=True, user_verified=True, hardware_backed=True,
                      phishing_resistant=True, sign_count_observed=True, freshness_seconds=1)
    score = score_event(sig)
    d = evaluate_policy(p, phishing_resistant=True, user_verified=True, assurance=score)
    assert d.allow


def test_min_assurance_denies_low_score():
    p = Policy(min_assurance=90, min_aal=1)
    score = score_event(SignalInput(user_present=True, phishing_resistant=True))
    d = evaluate_policy(p, phishing_resistant=True, assurance=score)
    assert not d.allow


def test_min_aal_without_score_denies():
    p = Policy(min_aal=3)
    d = evaluate_policy(p, phishing_resistant=True)
    assert not d.allow


def test_format_restriction():
    p = Policy(allowed_formats=["packed"])
    assert not evaluate_policy(p, phishing_resistant=True, attestation_format="none").allow
    assert evaluate_policy(p, phishing_resistant=True, attestation_format="packed").allow


def test_decision_to_dict():
    p = Policy()
    d = evaluate_policy(p, phishing_resistant=True)
    assert set(d.to_dict()) >= {"allow", "policy", "reasons", "matched"}
