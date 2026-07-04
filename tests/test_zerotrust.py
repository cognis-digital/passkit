from passkit.zerotrust import AAL, SignalInput, score_event


def test_full_hardware_passkey_is_aal3():
    sig = SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=True, sign_count_ok=True, sign_count_observed=True,
        freshness_seconds=2,
    )
    score = score_event(sig)
    assert score.level == AAL.AAL3
    assert score.score >= 85


def test_software_verified_passkey_is_aal2():
    sig = SignalInput(
        user_present=True, user_verified=True, hardware_backed=False,
        phishing_resistant=True, sign_count_observed=True, freshness_seconds=10,
    )
    score = score_event(sig)
    assert score.level == AAL.AAL2


def test_non_phishing_resistant_caps_at_aal1():
    sig = SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=False,
    )
    score = score_event(sig)
    assert score.level == AAL.AAL1


def test_clone_warning_penalizes():
    sig = SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=True, sign_count_ok=False,
    )
    score = score_event(sig)
    assert any("clone" in c.lower() for c in score.caveats)
    # clone regression prevents AAL3
    assert score.level != AAL.AAL3


def test_stale_challenge_zero_freshness():
    sig = SignalInput(
        user_present=True, user_verified=True, phishing_resistant=True,
        freshness_seconds=600, max_freshness_seconds=300,
    )
    score = score_event(sig)
    fresh = [s for s in score.signals if s.name == "freshness"][0]
    assert fresh.points == 0
    assert any("TTL" in c for c in score.caveats)


def test_unknown_hardware_partial_credit():
    sig = SignalInput(user_present=True, phishing_resistant=True, hardware_backed=None)
    score = score_event(sig)
    hw = [s for s in score.signals if s.name == "hardware_backed"][0]
    assert hw.points == 5


def test_score_bounded_0_100():
    empty = score_event(SignalInput())
    assert 0 <= empty.score <= 100
    full = score_event(SignalInput(
        user_present=True, user_verified=True, hardware_backed=True,
        phishing_resistant=True, sign_count_observed=True, freshness_seconds=0,
    ))
    assert full.score == 100


def test_breakdown_is_explainable():
    score = score_event(SignalInput(user_present=True, phishing_resistant=True))
    text = score.breakdown()
    assert "user_present" in text
    assert "phishing_resistant" in text


def test_to_dict_shape():
    d = score_event(SignalInput(user_present=True)).to_dict()
    assert set(d) >= {"score", "level", "signals", "caveats"}
    assert isinstance(d["signals"], list)


def test_negative_freshness_flagged():
    score = score_event(SignalInput(
        user_present=True, phishing_resistant=True, freshness_seconds=-1
    ))
    assert any("negative" in c.lower() for c in score.caveats)


def test_empty_event_is_aal1_low_score():
    score = score_event(SignalInput())
    assert score.level == AAL.AAL1
    assert score.score < 30
