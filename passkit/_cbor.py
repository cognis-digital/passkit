"""Minimal, dependency-free CBOR decoder (RFC 8949 subset).

WebAuthn uses CBOR for attestation objects and COSE keys. We only need the
data-item types that actually appear there: unsigned/negative integers, byte
strings, text strings, arrays, maps, and the simple values true/false/null.
Floats and tags are decoded where trivial and otherwise rejected so we never
silently mis-parse a structure we are about to make a security decision on.

This is intentionally a *decoder* only. It is strict: trailing bytes and
non-canonical/unsupported major types raise ``CBORError`` rather than being
skipped, because lenient parsing of security-critical blobs is a footgun.
"""

from __future__ import annotations

from typing import Any, Tuple


class CBORError(ValueError):
    """Raised when a CBOR item cannot be decoded."""


def loads(data: bytes) -> Any:
    """Decode a single CBOR item from *data*; reject trailing bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise CBORError("CBOR input must be bytes")
    value, offset = _decode(bytes(data), 0)
    if offset != len(data):
        raise CBORError(
            f"trailing bytes after CBOR item ({len(data) - offset} left)"
        )
    return value


def decode_first(data: bytes) -> Tuple[Any, int]:
    """Decode the first CBOR item, returning (value, bytes_consumed).

    Used for attestation objects where the authenticatorData byte string is
    followed by other structures we handle separately.
    """
    return _decode(bytes(data), 0)


def _read_length(data: bytes, offset: int, info: int) -> Tuple[int, int]:
    """Resolve the argument for a major type. Returns (value, new_offset)."""
    if info < 24:
        return info, offset
    if info == 24:
        _need(data, offset, 1)
        return data[offset], offset + 1
    if info == 25:
        _need(data, offset, 2)
        return int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    if info == 26:
        _need(data, offset, 4)
        return int.from_bytes(data[offset:offset + 4], "big"), offset + 4
    if info == 27:
        _need(data, offset, 8)
        return int.from_bytes(data[offset:offset + 8], "big"), offset + 8
    raise CBORError(f"unsupported/indefinite length encoding (info={info})")


def _need(data: bytes, offset: int, n: int) -> None:
    if offset + n > len(data):
        raise CBORError("truncated CBOR item")


def _decode(data: bytes, offset: int) -> Tuple[Any, int]:
    _need(data, offset, 1)
    initial = data[offset]
    offset += 1
    major = initial >> 5
    info = initial & 0x1F

    if major == 0:  # unsigned int
        return _read_length(data, offset, info)

    if major == 1:  # negative int
        value, offset = _read_length(data, offset, info)
        return -1 - value, offset

    if major == 2:  # byte string
        length, offset = _read_length(data, offset, info)
        _need(data, offset, length)
        return data[offset:offset + length], offset + length

    if major == 3:  # text string
        length, offset = _read_length(data, offset, info)
        _need(data, offset, length)
        try:
            return data[offset:offset + length].decode("utf-8"), offset + length
        except UnicodeDecodeError as exc:
            raise CBORError("invalid UTF-8 in CBOR text string") from exc

    if major == 4:  # array
        length, offset = _read_length(data, offset, info)
        items = []
        for _ in range(length):
            item, offset = _decode(data, offset)
            items.append(item)
        return items, offset

    if major == 5:  # map
        length, offset = _read_length(data, offset, info)
        result: dict = {}
        for _ in range(length):
            key, offset = _decode(data, offset)
            if isinstance(key, (bytes, bytearray)):
                key = bytes(key)
            val, offset = _decode(data, offset)
            if key in result:
                raise CBORError("duplicate key in CBOR map")
            result[key] = val
        return result, offset

    if major == 6:  # tag - decode and discard tag number
        _tag, offset = _read_length(data, offset, info)
        return _decode(data, offset)

    if major == 7:  # simple / float
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        if info == 23:
            return None, offset  # undefined -> None
        raise CBORError(f"unsupported simple/float value (info={info})")

    raise CBORError(f"unsupported CBOR major type {major}")


def _encode_head(major: int, arg: int) -> bytes:
    """Encode a CBOR item head (major type + argument), canonical minimal form."""
    mt = major << 5
    if arg < 24:
        return bytes([mt | arg])
    if arg < 0x100:
        return bytes([mt | 24, arg])
    if arg < 0x10000:
        return bytes([mt | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([mt | 26]) + arg.to_bytes(4, "big")
    return bytes([mt | 27]) + arg.to_bytes(8, "big")


def dumps(value: Any) -> bytes:
    """Encode *value* to canonical (RFC 8949 core deterministic) CBOR.

    Supports the same subset as ``loads``. Map keys are sorted by their
    encoded byte representation for deterministic, canonical output — which
    matters for reproducible test vectors.
    """
    if value is True:
        return bytes([0xE0 | 21])
    if value is False:
        return bytes([0xE0 | 20])
    if value is None:
        return bytes([0xE0 | 22])
    if isinstance(value, bool):  # defensive; handled above
        return dumps(bool(value))
    if isinstance(value, int):
        if value >= 0:
            return _encode_head(0, value)
        return _encode_head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _encode_head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _encode_head(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        out = _encode_head(4, len(value))
        for item in value:
            out += dumps(item)
        return out
    if isinstance(value, dict):
        encoded_items = [(dumps(k), dumps(v)) for k, v in value.items()]
        encoded_items.sort(key=lambda kv: kv[0])
        out = _encode_head(5, len(encoded_items))
        for k, v in encoded_items:
            out += k + v
        return out
    raise CBORError(f"cannot encode value of type {type(value).__name__}")
