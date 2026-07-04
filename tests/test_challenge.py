import time

import pytest

from passkit.challenge import ChallengeStore, build_challenge, build_deeplink, build_qr_payload
from passkit.challenge.builder import verify_challenge_payload
from passkit.errors import ChallengeError


def test_issue_and_consume_once():
    store = ChallengeStore()
    ch = store.issue()
    consumed = store.consume(ch.id)
    assert consumed.value == ch.value


def test_replay_rejected():
    store = ChallengeStore()
    ch = store.issue()
    store.consume(ch.id)
    with pytest.raises(ChallengeError) as e:
        store.consume(ch.id)
    assert e.value.code == "replay_or_unknown"


def test_unknown_rejected():
    store = ChallengeStore()
    with pytest.raises(ChallengeError):
        store.consume("nope")


def test_expiry_rejected():
    store = ChallengeStore(ttl_seconds=1)
    ch = store.issue()
    # simulate expiry by rewinding the stored expiry time
    stored = store._backend._items[ch.id]  # type: ignore[attr-defined]
    stored.expires_at = time.time() - 5
    with pytest.raises(ChallengeError):
        store.consume(ch.id)


def test_challenge_entropy_length():
    store = ChallengeStore(challenge_bytes=32)
    ch = store.issue()
    assert len(ch.value) == 32


def test_challenges_are_unique():
    store = ChallengeStore()
    ids = {store.issue().id for _ in range(200)}
    assert len(ids) == 200


def test_purge_expired():
    store = ChallengeStore(ttl_seconds=1)
    for _ in range(5):
        ch = store.issue()
        store._backend._items[ch.id].expires_at = time.time() - 5  # type: ignore
    removed = store.purge_expired()
    assert removed == 5
    assert len(store) == 0


def test_rejects_bad_config():
    with pytest.raises(ValueError):
        ChallengeStore(ttl_seconds=0)
    with pytest.raises(ValueError):
        ChallengeStore(challenge_bytes=8)


def test_context_carried():
    store = ChallengeStore()
    ch = store.issue(context={"user": "alice"})
    assert store.consume(ch.id).context["user"] == "alice"


def test_build_challenge_payload_and_tag_verify():
    store = ChallengeStore()
    ch = store.issue()
    key = b"secret-hmac-key"
    payload = build_challenge(ch, "example.mil", ["https://example.mil"], hmac_key=key)
    body = verify_challenge_payload(payload, key)
    assert body["rpId"] == "example.mil"


def test_build_challenge_tampered_tag_rejected():
    store = ChallengeStore()
    ch = store.issue()
    key = b"k"
    payload = build_challenge(ch, "example.mil", ["https://example.mil"], hmac_key=key)
    payload["body"]["rpId"] = "evil.mil"
    with pytest.raises(ValueError):
        verify_challenge_payload(payload, key)


def test_deeplink_format():
    store = ChallengeStore()
    ch = store.issue()
    link = build_deeplink(ch, "example.mil")
    assert link.startswith("passkit://auth?")
    assert "challenge=" in link


def test_qr_svg_structure():
    svg = build_qr_payload("passkit://auth?challenge=abc")
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert "<rect" in svg


def test_qr_deterministic():
    a = build_qr_payload("https://example.mil/auth?x=1")
    b = build_qr_payload("https://example.mil/auth?x=1")
    assert a == b
