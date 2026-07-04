"""Parser + validator for clientDataJSON.

clientDataJSON is a UTF-8 JSON serialization the browser produces and the
authenticator signs over (indirectly, via its SHA-256 hash appended to
authenticatorData). It carries the three fields that make WebAuthn
phishing-resistant when the verifier checks them:

    type       "webauthn.create" (registration) or "webauthn.get" (assertion)
    challenge  base64url(no padding) of the server-issued challenge
    origin     the fully-qualified origin the ceremony ran on

Binding the signed challenge + origin is what stops a lookalike phishing
domain from relaying a credential: the origin it forces the browser to sign
will not match the legitimate RP origin, so verification fails.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from passkit._util import b64url_decode
from passkit.errors import VerificationError


@dataclass
class ClientData:
    type: str
    challenge: bytes  # decoded raw challenge bytes
    origin: str
    cross_origin: Optional[bool]
    raw: bytes
    parsed: Dict[str, Any]


def parse_client_data(data: bytes) -> ClientData:
    """Parse clientDataJSON bytes. Raises VerificationError on malformed input."""
    if not isinstance(data, (bytes, bytearray)):
        raise VerificationError("clientDataJSON must be bytes", "bad_clientdata")
    data = bytes(data)
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(
            f"clientDataJSON is not valid JSON: {exc}", "bad_clientdata"
        ) from exc
    if not isinstance(parsed, dict):
        raise VerificationError("clientDataJSON is not an object", "bad_clientdata")

    ctype = parsed.get("type")
    challenge_b64 = parsed.get("challenge")
    origin = parsed.get("origin")
    if not isinstance(ctype, str):
        raise VerificationError("clientData.type missing", "bad_clientdata")
    if not isinstance(challenge_b64, str):
        raise VerificationError("clientData.challenge missing", "bad_clientdata")
    if not isinstance(origin, str):
        raise VerificationError("clientData.origin missing", "bad_clientdata")

    try:
        challenge = b64url_decode(challenge_b64)
    except Exception as exc:  # noqa: BLE001 - normalize to VerificationError
        raise VerificationError(
            f"clientData.challenge is not valid base64url: {exc}", "bad_clientdata"
        ) from exc

    cross_origin = parsed.get("crossOrigin")
    if cross_origin is not None and not isinstance(cross_origin, bool):
        raise VerificationError("clientData.crossOrigin not boolean", "bad_clientdata")

    return ClientData(
        type=ctype,
        challenge=challenge,
        origin=origin,
        cross_origin=cross_origin,
        raw=data,
        parsed=parsed,
    )


__all__ = ["ClientData", "parse_client_data"]
