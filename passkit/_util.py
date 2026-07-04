"""Small shared utilities: base64url, constant-time compare, origin handling."""

from __future__ import annotations

import base64
import hashlib
import hmac
from urllib.parse import urlsplit


def b64url_decode(value) -> bytes:
    """Decode base64url (with or without padding). Accepts str or bytes."""
    if isinstance(value, bytes):
        value = value.decode("ascii")
    value = value.strip()
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url (WebAuthn convention)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison."""
    return hmac.compare_digest(bytes(a), bytes(b))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(bytes(data)).digest()


def normalize_origin(origin: str) -> str:
    """Normalize an origin to scheme://host[:port], lowercasing scheme+host.

    Default ports (443 for https, 80 for http) are dropped so that
    ``https://example.com`` and ``https://example.com:443`` compare equal.
    Raises ValueError on an origin without a scheme+host.
    """
    parts = urlsplit(origin)
    if not parts.scheme or not parts.hostname:
        raise ValueError(f"invalid origin: {origin!r}")
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    port = parts.port
    default_ports = {"https": 443, "http": 80}
    if port is None or default_ports.get(scheme) == port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def rp_id_hash(rp_id: str) -> bytes:
    """SHA-256 of the RP ID, as stored in authenticatorData.rpIdHash."""
    return sha256(rp_id.encode("utf-8"))


__all__ = [
    "b64url_decode",
    "b64url_encode",
    "constant_time_equals",
    "sha256",
    "normalize_origin",
    "rp_id_hash",
]
