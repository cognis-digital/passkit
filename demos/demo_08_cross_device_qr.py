"""Demo 8: cross-device challenge — deeplink, signed payload, and QR SVG.

For hybrid auth (scan a QR on a kiosk with your phone), the verifier hands the
client a compact, HMAC-tagged payload and a QR/deeplink. The tag lets the
returning payload be checked for tampering.
"""

import os

from passkit.challenge import (
    ChallengeStore,
    build_challenge,
    build_deeplink,
    build_qr_payload,
)
from passkit.challenge.builder import verify_challenge_payload


def main() -> int:
    store = ChallengeStore()
    ch = store.issue(context={"flow": "cross-device"})
    hmac_key = os.urandom(32)

    payload = build_challenge(
        ch, "login.example.mil", ["https://login.example.mil"], hmac_key=hmac_key
    )
    print("[payload] signed cross-device challenge built")
    print(f"[payload] challenge={payload['body']['challenge'][:20]}... "
          f"exp={payload['body']['exp']}")

    deeplink = build_deeplink(ch, "login.example.mil")
    print(f"[deeplink] {deeplink[:60]}...")

    svg = build_qr_payload(deeplink)
    out = os.path.join(os.path.dirname(__file__), "cross_device_qr.svg")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(svg)
    print(f"[qr] wrote {len(svg)} bytes of SVG to {os.path.basename(out)}")

    # Tamper detection on return.
    body = verify_challenge_payload(payload, hmac_key)
    print(f"[verify] payload tag valid, rpId={body['rpId']}")

    payload["body"]["rpId"] = "evil.mil"
    try:
        verify_challenge_payload(payload, hmac_key)
        print("[demo 8] FAIL: tampered payload accepted")
        return 1
    except ValueError:
        print("[defense] tampered payload REJECTED (HMAC mismatch)")

    print("[demo 8] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
