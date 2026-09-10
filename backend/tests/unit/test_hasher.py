"""
Unit tests for cryptographic evidence hasher.
"""

from app.modules.evidence.hasher import canonicalize_payload, compute_sha256


def test_hasher_deterministic_for_dict_key_ordering():
    payload_a = {"EventID": 1, "Image": "cmd.exe", "User": "SYSTEM"}
    payload_b = {"User": "SYSTEM", "EventID": 1, "Image": "cmd.exe"}

    hash_a = compute_sha256(payload_a)
    hash_b = compute_sha256(payload_b)

    assert hash_a == hash_b
    assert len(hash_a) == 64


def test_hasher_string_input():
    raw_str = '{"EventID": 1, "Image": "cmd.exe"}'
    hash_val = compute_sha256(raw_str)
    assert len(hash_val) == 64


def test_hasher_different_content_produces_different_hash():
    payload_a = {"EventID": 1, "Image": "cmd.exe"}
    payload_b = {"EventID": 1, "Image": "powershell.exe"}

    assert compute_sha256(payload_a) != compute_sha256(payload_b)


def test_canonicalize_payload_json():
    data = {"b": 2, "a": 1}
    canonical = canonicalize_payload(data)
    assert canonical == '{"a":1,"b":2}'
