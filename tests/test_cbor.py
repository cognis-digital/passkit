import pytest

from passkit import _cbor


@pytest.mark.parametrize("value", [
    0, 1, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296,
    -1, -24, -256, -1000000,
])
def test_int_roundtrip(value):
    assert _cbor.loads(_cbor.dumps(value)) == value


def test_bytes_and_text_roundtrip():
    assert _cbor.loads(_cbor.dumps(b"\x00\x01\x02")) == b"\x00\x01\x02"
    assert _cbor.loads(_cbor.dumps("hello")) == "hello"
    assert _cbor.loads(_cbor.dumps("héllo €")) == "héllo €"


def test_array_and_map_roundtrip():
    obj = {"fmt": "none", "n": [1, 2, 3], "b": b"xyz", 1: 2, -7: True}
    assert _cbor.loads(_cbor.dumps(obj)) == obj


def test_simple_values():
    assert _cbor.loads(_cbor.dumps(True)) is True
    assert _cbor.loads(_cbor.dumps(False)) is False
    assert _cbor.loads(_cbor.dumps(None)) is None


def test_canonical_map_key_ordering_is_deterministic():
    a = _cbor.dumps({1: "a", 2: "b", 3: "c"})
    b = _cbor.dumps({3: "c", 1: "a", 2: "b"})
    assert a == b


def test_trailing_bytes_rejected():
    payload = _cbor.dumps(1) + b"\xff"
    with pytest.raises(_cbor.CBORError):
        _cbor.loads(payload)


def test_truncated_rejected():
    with pytest.raises(_cbor.CBORError):
        _cbor.loads(b"\x42\x00")  # says 2-byte string, only 1 byte


def test_duplicate_map_key_rejected():
    # two entries with key 1
    payload = bytes([0xA2, 0x01, 0x01, 0x01, 0x02])
    with pytest.raises(_cbor.CBORError):
        _cbor.loads(payload)


def test_indefinite_length_rejected():
    with pytest.raises(_cbor.CBORError):
        _cbor.loads(bytes([0x5F, 0xFF]))  # indefinite byte string


def test_decode_first_reports_consumed():
    payload = _cbor.dumps(b"abc") + _cbor.dumps("tail")
    value, consumed = _cbor.decode_first(payload)
    assert value == b"abc"
    assert payload[consumed:] == _cbor.dumps("tail")


def test_non_bytes_input_rejected():
    with pytest.raises(_cbor.CBORError):
        _cbor.loads("not bytes")


def test_unencodable_type_rejected():
    with pytest.raises(_cbor.CBORError):
        _cbor.dumps(object())
