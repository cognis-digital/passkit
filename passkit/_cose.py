"""COSE key handling and signature verification.

Maps COSE_Key structures (RFC 8152) into ``cryptography`` public keys and
verifies signatures. We support the two algorithms mandated for broad
interop in practice:

    ES256  (-7)   ECDSA over P-256 with SHA-256
    RS256  (-257) RSASSA-PKCS1-v1_5 with SHA-256

COSE key common labels:
    1  kty   (2 = EC2, 3 = RSA)
    3  alg
EC2 (kty=2):
    -1 crv  (1 = P-256)
    -2 x
    -3 y
RSA (kty=3):
    -1 n
    -2 e
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from passkit._cbor import loads as cbor_loads

COSE_KTY = 1
COSE_ALG = 3
COSE_CRV = -1
COSE_EC_X = -2
COSE_EC_Y = -3
COSE_RSA_N = -1
COSE_RSA_E = -2

KTY_EC2 = 2
KTY_RSA = 3

ALG_ES256 = -7
ALG_RS256 = -257

CRV_P256 = 1

ALG_NAMES = {ALG_ES256: "ES256", ALG_RS256: "RS256"}


class COSEError(ValueError):
    """Raised on malformed or unsupported COSE keys / algorithms."""


@dataclass
class COSEKey:
    """A parsed COSE public key ready for signature verification."""

    kty: int
    alg: int
    public_key: Any  # cryptography public key object
    raw: Dict[Any, Any]

    @property
    def alg_name(self) -> str:
        return ALG_NAMES.get(self.alg, f"alg({self.alg})")


def parse_cose_key(data) -> COSEKey:
    """Parse a COSE_Key from CBOR bytes or an already-decoded dict."""
    cose = cbor_loads(data) if isinstance(data, (bytes, bytearray)) else data
    if not isinstance(cose, dict):
        raise COSEError("COSE key is not a CBOR map")

    kty = cose.get(COSE_KTY)
    alg = cose.get(COSE_ALG)
    if kty is None:
        raise COSEError("COSE key missing kty")
    if alg is None:
        raise COSEError("COSE key missing alg")

    if kty == KTY_EC2:
        if alg != ALG_ES256:
            raise COSEError(f"unsupported EC2 alg {alg} (only ES256)")
        crv = cose.get(COSE_CRV)
        if crv != CRV_P256:
            raise COSEError(f"unsupported EC curve {crv} (only P-256)")
        x = cose.get(COSE_EC_X)
        y = cose.get(COSE_EC_Y)
        if not isinstance(x, (bytes, bytearray)) or not isinstance(y, (bytes, bytearray)):
            raise COSEError("EC2 key missing x/y coordinates")
        if len(x) != 32 or len(y) != 32:
            raise COSEError("EC2 P-256 coordinates must be 32 bytes")
        pub_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            ec.SECP256R1(),
        )
        public_key = pub_numbers.public_key()
        return COSEKey(kty=kty, alg=alg, public_key=public_key, raw=cose)

    if kty == KTY_RSA:
        if alg != ALG_RS256:
            raise COSEError(f"unsupported RSA alg {alg} (only RS256)")
        n = cose.get(COSE_RSA_N)
        e = cose.get(COSE_RSA_E)
        if not isinstance(n, (bytes, bytearray)) or not isinstance(e, (bytes, bytearray)):
            raise COSEError("RSA key missing n/e")
        pub_numbers = rsa.RSAPublicNumbers(
            int.from_bytes(e, "big"),
            int.from_bytes(n, "big"),
        )
        if pub_numbers.n.bit_length() < 2048:
            raise COSEError("RSA modulus < 2048 bits rejected")
        public_key = pub_numbers.public_key()
        return COSEKey(kty=kty, alg=alg, public_key=public_key, raw=cose)

    raise COSEError(f"unsupported COSE kty {kty}")


def verify_signature(key: COSEKey, message: bytes, signature: bytes) -> bool:
    """Verify *signature* over *message* using *key*. Returns True/False.

    Never raises on a bad signature — returns False — so callers get a clean
    boolean. Structural/parameter problems still raise COSEError.
    """
    try:
        if key.alg == ALG_ES256:
            # WebAuthn ECDSA signatures are ASN.1 DER encoded (r,s).
            key.public_key.verify(
                bytes(signature),
                bytes(message),
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        if key.alg == ALG_RS256:
            key.public_key.verify(
                bytes(signature),
                bytes(message),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        raise COSEError(f"cannot verify unsupported alg {key.alg}")
    except InvalidSignature:
        return False


def public_key_to_cose(public_key, alg: int) -> bytes:
    """Encode a cryptography public key as a canonical COSE_Key (CBOR bytes).

    Helper for tests / test-vector generation. Produces deterministic bytes.
    """
    from passkit._cbor import dumps as cbor_dumps

    if alg == ALG_ES256 and isinstance(public_key, ec.EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        cose = {
            COSE_KTY: KTY_EC2,
            COSE_ALG: ALG_ES256,
            COSE_CRV: CRV_P256,
            COSE_EC_X: numbers.x.to_bytes(32, "big"),
            COSE_EC_Y: numbers.y.to_bytes(32, "big"),
        }
        return cbor_dumps(cose)
    if alg == ALG_RS256 and isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        n_len = (numbers.n.bit_length() + 7) // 8
        e_len = (numbers.e.bit_length() + 7) // 8
        cose = {
            COSE_KTY: KTY_RSA,
            COSE_ALG: ALG_RS256,
            COSE_RSA_N: numbers.n.to_bytes(n_len, "big"),
            COSE_RSA_E: numbers.e.to_bytes(e_len, "big"),
        }
        return cbor_dumps(cose)
    raise COSEError("unsupported key/alg for COSE encoding")


__all__ = [
    "COSEKey",
    "COSEError",
    "parse_cose_key",
    "verify_signature",
    "public_key_to_cose",
    "ALG_ES256",
    "ALG_RS256",
    "ALG_NAMES",
]
