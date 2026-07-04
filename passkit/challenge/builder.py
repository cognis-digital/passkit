"""Cross-device challenge builders: deeplinks and QR payloads.

For hybrid / cross-device authentication (scan a QR on a kiosk with your
phone), the verifier needs to hand the client a compact, tamper-evident
payload carrying the challenge, RP, and allowed origins. We build a signed
(HMAC) URL-safe payload plus a matching deeplink, and render a QR code as an
SVG string with no third-party dependency.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict, List, Optional
from urllib.parse import urlencode

from passkit._util import b64url_decode, b64url_encode, constant_time_equals
from passkit.challenge.store import Challenge


def build_challenge(
    challenge: Challenge,
    rp_id: str,
    origins: List[str],
    *,
    hmac_key: Optional[bytes] = None,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, object]:
    """Build a transport payload for a cross-device ceremony.

    If ``hmac_key`` is provided the payload is tagged so the responding device
    (or a re-presenting client) can be checked for tamper on return.
    """
    body = {
        "v": 1,
        "challenge": challenge.value_b64,
        "rpId": rp_id,
        "origins": list(origins),
        "exp": int(challenge.expires_at),
        "cid": challenge.id,
    }
    if extra:
        body["ctx"] = dict(extra)
    payload = {"body": body}
    if hmac_key is not None:
        payload["tag"] = _tag(body, hmac_key)
    return payload


def verify_challenge_payload(payload: Dict[str, object], hmac_key: bytes) -> Dict:
    """Verify the HMAC tag on a returned payload; return the body or raise."""
    body = payload.get("body")
    tag = payload.get("tag")
    if not isinstance(body, dict) or not isinstance(tag, str):
        raise ValueError("payload missing body or tag")
    expected = _tag(body, hmac_key)
    if not constant_time_equals(tag.encode(), expected.encode()):
        raise ValueError("payload HMAC tag mismatch (tampered)")
    return body


def _tag(body: Dict, hmac_key: bytes) -> str:
    serialized = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return b64url_encode(hmac.new(hmac_key, serialized, hashlib.sha256).digest())


def build_deeplink(
    challenge: Challenge, rp_id: str, scheme: str = "passkit"
) -> str:
    """Build an app deeplink like ``passkit://auth?...`` for a challenge."""
    params = urlencode(
        {"rpId": rp_id, "challenge": challenge.value_b64, "cid": challenge.id}
    )
    return f"{scheme}://auth?{params}"


def build_qr_payload(data: str, *, module_px: int = 6, quiet: int = 4) -> str:
    """Render *data* as a QR-code SVG string (no external deps).

    Implements a byte-mode QR encoder (versions 1-10, error-correction level M)
    sufficient for auth deeplinks/URLs. Returns a standalone SVG document.
    """
    matrix = _qr_matrix(data)
    n = len(matrix)
    size = (n + 2 * quiet) * module_px
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 {size} {size}" shape-rendering="crispEdges">',
        f'<rect width="{size}" height="{size}" fill="#ffffff"/>',
    ]
    for r in range(n):
        for c in range(n):
            if matrix[r][c]:
                x = (c + quiet) * module_px
                y = (r + quiet) * module_px
                parts.append(
                    f'<rect x="{x}" y="{y}" width="{module_px}" '
                    f'height="{module_px}" fill="#000000"/>'
                )
    parts.append("</svg>")
    return "".join(parts)


# --- Minimal QR encoder (byte mode, EC level M) -----------------------------
# Compact but real: Reed-Solomon over GF(256), standard masking + format info.

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _init_gf() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(n: int) -> List[int]:
    g = [1]
    for i in range(n):
        g2 = [0] * (len(g) + 1)
        for j in range(len(g)):
            g2[j] ^= _gf_mul(g[j], 1)
            g2[j + 1] ^= _gf_mul(g[j], _GF_EXP[i])
        g = g2
    return g


def _rs_encode(data: List[int], ec_len: int) -> List[int]:
    gen = _rs_generator(ec_len)
    res = data + [0] * ec_len
    for i in range(len(data)):
        coef = res[i]
        if coef != 0:
            for j in range(len(gen)):
                res[i + j] ^= _gf_mul(gen[j], coef)
    return res[len(data):]


# (total_codewords, ec_per_block, num_blocks) for EC level M, versions 1..10.
_VERSION_M = {
    1: (26, 10, 1),
    2: (44, 16, 1),
    3: (70, 26, 1),
    4: (100, 18, 2),
    5: (134, 24, 2),
    6: (172, 16, 4),
    7: (196, 18, 4),
    8: (242, 22, 4),
    9: (292, 22, 5),
    10: (346, 26, 5),
}


def _capacity_bytes(version: int) -> int:
    total, ec, blocks = _VERSION_M[version]
    data_codewords = total - ec * blocks
    # byte mode overhead: 4 bits mode + char count (8 bits v1-9, 16 v>=10)
    count_bits = 16 if version >= 10 else 8
    overhead_bits = 4 + count_bits
    return (data_codewords * 8 - overhead_bits) // 8


def _choose_version(length: int) -> int:
    for v in range(1, 11):
        if length <= _capacity_bytes(v):
            return v
    raise ValueError("data too long for QR versions 1-10 (byte mode, EC-M)")


def _qr_matrix(text: str) -> List[List[int]]:
    data = text.encode("utf-8")
    version = _choose_version(len(data))
    total, ec_per_block, num_blocks = _VERSION_M[version]
    data_codewords = total - ec_per_block * num_blocks

    # Build the bitstream.
    bits: List[int] = []

    def put(value: int, n: int) -> None:
        for i in range(n - 1, -1, -1):
            bits.append((value >> i) & 1)

    count_bits = 16 if version >= 10 else 8
    put(0b0100, 4)  # byte mode
    put(len(data), count_bits)
    for b in data:
        put(b, 8)
    # terminator + pad to byte boundary
    put(0, min(4, data_codewords * 8 - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = [0xEC, 0x11]
    i = 0
    while len(codewords) < data_codewords:
        codewords.append(pad[i % 2])
        i += 1

    # Split into blocks, compute EC, interleave.
    per_block = data_codewords // num_blocks
    remainder = data_codewords % num_blocks
    blocks_data: List[List[int]] = []
    blocks_ec: List[List[int]] = []
    idx = 0
    for b in range(num_blocks):
        size = per_block + (1 if b >= num_blocks - remainder else 0)
        block = codewords[idx:idx + size]
        idx += size
        blocks_data.append(block)
        blocks_ec.append(_rs_encode(block, ec_per_block))

    final: List[int] = []
    max_data = max(len(b) for b in blocks_data)
    for i in range(max_data):
        for b in blocks_data:
            if i < len(b):
                final.append(b[i])
    for i in range(ec_per_block):
        for b in blocks_ec:
            final.append(b[i])

    final_bits: List[int] = []
    for cw in final:
        for i in range(7, -1, -1):
            final_bits.append((cw >> i) & 1)

    return _place_and_mask(version, final_bits)


def _place_and_mask(version: int, data_bits: List[int]) -> List[List[int]]:
    size = version * 4 + 17
    m = [[None] * size for _ in range(size)]  # type: ignore
    reserved = [[False] * size for _ in range(size)]

    def place_finder(r0: int, c0: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = r0 + r, c0 + c
                if 0 <= rr < size and 0 <= cc < size:
                    inring = (
                        0 <= r <= 6 and 0 <= c <= 6 and (
                            r in (0, 6) or c in (0, 6)
                            or (2 <= r <= 4 and 2 <= c <= 4)
                        )
                    )
                    m[rr][cc] = 1 if inring else 0
                    reserved[rr][cc] = True

    place_finder(0, 0)
    place_finder(0, size - 7)
    place_finder(size - 7, 0)

    # timing patterns
    for i in range(size):
        if m[6][i] is None:
            m[6][i] = 1 if i % 2 == 0 else 0
            reserved[6][i] = True
        if m[i][6] is None:
            m[i][6] = 1 if i % 2 == 0 else 0
            reserved[i][6] = True

    # alignment pattern (single, for versions 2-6 center; skip for v1)
    _place_alignment(version, size, m, reserved)

    # dark module
    m[size - 8][8] = 1
    reserved[size - 8][8] = True

    # reserve format info areas
    for i in range(9):
        for (r, c) in ((8, i), (i, 8)):
            if 0 <= r < size and 0 <= c < size and m[r][c] is None:
                reserved[r][c] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True
        reserved[size - 1 - i][8] = True

    # place data with zig-zag
    di = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        for _ in range(size):
            row = (size - 1 - _) if upward else _
            for c in (col, col - 1):
                if not reserved[row][c] and m[row][c] is None:
                    bit = data_bits[di] if di < len(data_bits) else 0
                    m[row][c] = bit
                    di += 1
        upward = not upward
        col -= 2

    # choose mask 0 (deterministic; valid) and apply
    mask = 0
    for r in range(size):
        for c in range(size):
            if not reserved[r][c] and m[r][c] is not None:
                if (r + c) % 2 == 0:
                    m[r][c] ^= 1

    _place_format(size, m, mask)

    return [[1 if v else 0 for v in row] for row in m]


def _place_alignment(version, size, m, reserved) -> None:
    if version < 2:
        return
    # centers for versions 2-6: single alignment at (size-7, size-7) region
    centers = {2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34]}
    if version not in centers:
        # For versions 7-10 use the standard tables (subset).
        tables = {
            7: [6, 22, 38],
            8: [6, 24, 42],
            9: [6, 26, 46],
            10: [6, 28, 50],
        }
        coords = tables.get(version)
        if not coords:
            return
    else:
        coords = centers[version]
    positions = [(r, c) for r in coords for c in coords]
    for (cr, cc) in positions:
        # skip if overlapping finder patterns
        if reserved[cr][cc] and m[cr][cc] is not None and cr <= 8 and cc <= 8:
            continue
        if (cr <= 8 and cc <= 8) or (cr <= 8 and cc >= size - 8) or (cr >= size - 8 and cc <= 8):
            continue
        for dr in range(-2, 3):
            for dc in range(-2, 3):
                rr, cc2 = cr + dr, cc + dc
                if 0 <= rr < size and 0 <= cc2 < size:
                    ring = max(abs(dr), abs(dc))
                    m[rr][cc2] = 1 if ring != 1 else 0
                    reserved[rr][cc2] = True


# format info for EC level M and mask pattern, with BCH + XOR mask.
_FORMAT_M = {
    0: 0b101010000010010,
    1: 0b101000100100101,
    2: 0b101111001111100,
    3: 0b101101101001011,
}


def _place_format(size, m, mask) -> None:
    fmt = _FORMAT_M[mask]
    bits = [(fmt >> i) & 1 for i in range(14, -1, -1)]
    # positions around top-left and split top-right/bottom-left
    coords1 = [
        (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
        (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8),
    ]
    for bit, (r, c) in zip(bits, coords1):
        m[r][c] = bit
    coords2 = [(size - 1 - i, 8) for i in range(7)] + [(8, size - 8 + i) for i in range(8)]
    for bit, (r, c) in zip(bits, coords2):
        m[r][c] = bit


__all__ = [
    "build_challenge",
    "verify_challenge_payload",
    "build_deeplink",
    "build_qr_payload",
]
