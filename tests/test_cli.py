import json
import os

import pytest

from passkit import testing as T
from passkit._util import b64url_encode
from passkit.cli import main

RP = "login.example.mil"
ORIGIN = "https://login.example.mil"


def _reg_json(challenge):
    cred, att, cd = T.build_registration(RP, ORIGIN, challenge)
    payload = {
        "attestationObject": b64url_encode(att),
        "clientDataJSON": b64url_encode(cd),
        "expectedChallenge": b64url_encode(challenge),
        "expectedOrigins": [ORIGIN],
        "rpId": RP,
    }
    return cred, payload


def test_cli_challenge(capsys):
    rc = main(["challenge", "--ttl", "60"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ttl_seconds"] == 60
    assert "challenge_b64url" in out


def test_cli_verify_registration(tmp_path, capsys):
    chal = os.urandom(32)
    _, payload = _reg_json(chal)
    f = tmp_path / "reg.json"
    f.write_text(json.dumps(payload))
    rc = main(["verify-registration", str(f)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert "credentialPublicKey" in out


def test_cli_verify_registration_bad_origin(tmp_path, capsys):
    chal = os.urandom(32)
    _, payload = _reg_json(chal)
    payload["expectedOrigins"] = ["https://evil.mil"]
    f = tmp_path / "reg.json"
    f.write_text(json.dumps(payload))
    rc = main(["verify-registration", str(f)])
    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert out["code"] == "origin_mismatch"


def test_cli_verify_assertion(tmp_path, capsys):
    chal = os.urandom(32)
    cred, payload = _reg_json(chal)
    f = tmp_path / "reg.json"
    f.write_text(json.dumps(payload))
    main(["verify-registration", str(f)])
    reg_out = json.loads(capsys.readouterr().out)

    chal2 = os.urandom(32)
    ad, cd, sig = T.build_assertion(cred, RP, ORIGIN, chal2, sign_count=3)
    apayload = {
        "credentialPublicKey": reg_out["credentialPublicKey"],
        "authenticatorData": b64url_encode(ad),
        "clientDataJSON": b64url_encode(cd),
        "signature": b64url_encode(sig),
        "expectedChallenge": b64url_encode(chal2),
        "expectedOrigins": [ORIGIN],
        "rpId": RP,
        "storedSignCount": 1,
    }
    af = tmp_path / "assert.json"
    af.write_text(json.dumps(apayload))
    rc = main(["verify-assertion", str(af)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["newSignCount"] == 3


def test_cli_score_text(tmp_path, capsys):
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({"userPresent": True, "phishingResistant": True,
                             "userVerified": True, "hardwareBacked": True,
                             "signCountObserved": True, "freshnessSeconds": 1}))
    rc = main(["score", str(f)])
    assert rc == 0
    assert "AAL3-like" in capsys.readouterr().out


def test_cli_score_json(tmp_path, capsys):
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({"userPresent": True}))
    rc = main(["score", "--json", str(f)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "score" in out


def test_cli_policy_check_allow(tmp_path, capsys):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"require_phishing_resistant": True, "allowed_origins": [ORIGIN]}))
    ev = tmp_path / "e.json"
    ev.write_text(json.dumps({"phishingResistant": True, "origin": ORIGIN}))
    rc = main(["policy-check", "--policy", str(pol), str(ev)])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["allow"] is True


def test_cli_policy_check_deny(tmp_path, capsys):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"require_phishing_resistant": True}))
    ev = tmp_path / "e.json"
    ev.write_text(json.dumps({"phishingResistant": False}))
    rc = main(["policy-check", "--policy", str(pol), str(ev)])
    assert rc == 1


def test_cli_report_writes_html(tmp_path, capsys):
    ev = tmp_path / "e.json"
    ev.write_text(json.dumps({"signals": {"userPresent": True, "phishingResistant": True,
                                          "userVerified": True, "hardwareBacked": True},
                              "subject": "test login", "rpId": RP}))
    out = tmp_path / "report.html"
    rc = main(["report", str(ev), "-o", str(out)])
    assert rc == 0
    html = out.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "Assurance report" in html


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
