"""Command-line interface for passkit.

Subcommands:
    challenge            issue a single-use challenge (JSON to stdout)
    verify-registration  verify a registration ceremony (JSON input)
    verify-assertion     verify an assertion ceremony (JSON input)
    score                score an auth event's assurance
    policy-check         evaluate an event against a policy file
    report               render an HTML assurance report

Ceremony inputs are JSON files with base64url-encoded byte fields, so the CLI
works over files/pipes and is friendly to air-gapped workflows.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from typing import Optional

from passkit import __version__
from passkit._util import b64url_decode, b64url_encode
from passkit.challenge import ChallengeStore
from passkit.errors import PassKitError
from passkit.policy import evaluate_policy, load_policy
from passkit.report import render_report
from passkit.webauthn import verify_assertion, verify_registration
from passkit.zerotrust import SignalInput, score_event


def _read_json(path: Optional[str]) -> dict:
    if path is None or path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _b(value: str) -> bytes:
    """Decode a base64url or base64 field to bytes."""
    try:
        return b64url_decode(value)
    except Exception:
        return base64.b64decode(value)


def cmd_challenge(args) -> int:
    store = ChallengeStore(ttl_seconds=args.ttl)
    ch = store.issue()
    out = {
        "id": ch.id,
        "challenge_b64url": ch.value_b64,
        "expires_at": int(ch.expires_at),
        "ttl_seconds": args.ttl,
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_verify_registration(args) -> int:
    data = _read_json(args.input)
    try:
        result = verify_registration(
            attestation_object=_b(data["attestationObject"]),
            client_data_json=_b(data["clientDataJSON"]),
            expected_challenge=_b(data["expectedChallenge"]),
            expected_origins=data["expectedOrigins"],
            rp_id=data["rpId"],
            require_user_verification=data.get("requireUserVerification", False),
        )
    except PassKitError as exc:
        print(json.dumps({"ok": False, "code": getattr(exc, "code", "error"),
                          "error": str(exc)}, indent=2))
        return 2
    out = {
        "ok": True,
        "credentialId": result.credential_id_b64,
        "credentialPublicKey": b64url_encode(result.credential_public_key),
        "signCount": result.sign_count,
        "aaguid": result.aaguid_hex,
        "userVerified": result.user_verified,
        "backupEligible": result.backup_eligible,
        "fmt": result.fmt,
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_verify_assertion(args) -> int:
    data = _read_json(args.input)
    try:
        result = verify_assertion(
            credential_public_key=_b(data["credentialPublicKey"]),
            authenticator_data=_b(data["authenticatorData"]),
            client_data_json=_b(data["clientDataJSON"]),
            signature=_b(data["signature"]),
            expected_challenge=_b(data["expectedChallenge"]),
            expected_origins=data["expectedOrigins"],
            rp_id=data["rpId"],
            stored_sign_count=data.get("storedSignCount", 0),
            require_user_verification=data.get("requireUserVerification", False),
        )
    except PassKitError as exc:
        print(json.dumps({"ok": False, "code": getattr(exc, "code", "error"),
                          "error": str(exc)}, indent=2))
        return 2
    out = {
        "ok": True,
        "newSignCount": result.new_sign_count,
        "userVerified": result.user_verified,
        "cloneWarning": result.clone_warning,
        "warnings": result.warnings,
    }
    print(json.dumps(out, indent=2))
    return 0 if not result.clone_warning else 3


def _signal_from_dict(d: dict) -> SignalInput:
    return SignalInput(
        user_present=d.get("userPresent", False),
        user_verified=d.get("userVerified", False),
        hardware_backed=d.get("hardwareBacked"),
        phishing_resistant=d.get("phishingResistant", False),
        sign_count_ok=d.get("signCountOk", True),
        sign_count_observed=d.get("signCountObserved", False),
        freshness_seconds=d.get("freshnessSeconds"),
        max_freshness_seconds=d.get("maxFreshnessSeconds", 300.0),
        attestation_type=d.get("attestationType"),
        aaguid_known=d.get("aaguidKnown", False),
        backup_eligible=d.get("backupEligible"),
    )


def cmd_score(args) -> int:
    data = _read_json(args.input)
    score = score_event(_signal_from_dict(data))
    if args.json:
        print(json.dumps(score.to_dict(), indent=2))
    else:
        print(score.breakdown())
    return 0


def cmd_policy_check(args) -> int:
    with open(args.policy, "r", encoding="utf-8") as fh:
        policy = load_policy(fh.read())
    data = _read_json(args.input)
    assurance = None
    if "signals" in data:
        assurance = score_event(_signal_from_dict(data["signals"]))
    decision = evaluate_policy(
        policy,
        phishing_resistant=data.get("phishingResistant", False),
        user_verified=data.get("userVerified", False),
        origin=data.get("origin"),
        aaguid=data.get("aaguid"),
        attestation_format=data.get("attestationFormat"),
        hardware_backed=data.get("hardwareBacked"),
        assurance=assurance,
    )
    print(json.dumps(decision.to_dict(), indent=2))
    return 0 if decision.allow else 1


def cmd_report(args) -> int:
    data = _read_json(args.input)
    score = score_event(_signal_from_dict(data.get("signals", data)))
    html_str = render_report(
        score,
        subject=data.get("subject", "authentication event"),
        rp_id=data.get("rpId"),
        origin=data.get("origin"),
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(html_str)
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(html_str)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="passkit", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"passkit {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("challenge", help="issue a single-use challenge")
    c.add_argument("--ttl", type=int, default=300, help="TTL seconds (default 300)")
    c.set_defaults(func=cmd_challenge)

    r = sub.add_parser("verify-registration", help="verify a registration ceremony")
    r.add_argument("input", nargs="?", help="JSON input file (default stdin)")
    r.set_defaults(func=cmd_verify_registration)

    a = sub.add_parser("verify-assertion", help="verify an assertion ceremony")
    a.add_argument("input", nargs="?", help="JSON input file (default stdin)")
    a.set_defaults(func=cmd_verify_assertion)

    s = sub.add_parser("score", help="score an auth event's assurance")
    s.add_argument("input", nargs="?", help="JSON input file (default stdin)")
    s.add_argument("--json", action="store_true", help="emit JSON instead of text")
    s.set_defaults(func=cmd_score)

    pc = sub.add_parser("policy-check", help="evaluate an event against a policy")
    pc.add_argument("--policy", required=True, help="policy YAML/JSON file")
    pc.add_argument("input", nargs="?", help="JSON event file (default stdin)")
    pc.set_defaults(func=cmd_policy_check)

    rp = sub.add_parser("report", help="render an HTML assurance report")
    rp.add_argument("input", nargs="?", help="JSON input file (default stdin)")
    rp.add_argument("-o", "--output", help="output HTML file (default stdout)")
    rp.set_defaults(func=cmd_report)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PassKitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (KeyError, ValueError) as exc:
        print(f"error: malformed input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
