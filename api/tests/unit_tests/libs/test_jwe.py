import base64
import json
from datetime import UTC, datetime

import pytest
from Crypto.Cipher import AES

from libs.jwe import JweDecodeError, decode_compact_jwe, parse_jwe_key, parse_rfc3339_nanos


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _build_compact_jwe(payload: dict[str, object], key: bytes) -> str:
    header = {"alg": "dir", "enc": "A256GCM"}
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    iv = b"\x00" * 12
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(header_b64.encode("utf-8"))
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(payload).encode("utf-8"))

    encrypted_key_b64 = ""
    return ".".join(
        [
            header_b64,
            encrypted_key_b64,
            _base64url_encode(iv),
            _base64url_encode(ciphertext),
            _base64url_encode(tag),
        ]
    )


def test_decode_compact_jwe_round_trip():
    key = b"0" * 32
    payload = {"Expiration": "2020-05-28T16:26:33.162265825+08:00", "StaffId": 123456, "LoginName": "zhangsan"}
    token = _build_compact_jwe(payload, key)

    result = decode_compact_jwe(token, key)

    assert result.header["alg"] == "dir"
    assert result.header["enc"] == "A256GCM"
    assert result.plaintext == payload


def test_decode_compact_jwe_rejects_wrong_key():
    key = b"0" * 32
    token = _build_compact_jwe({"value": "ok"}, key)

    wrong_key = b"1" * 32

    with pytest.raises(JweDecodeError):
        decode_compact_jwe(token, wrong_key)


def test_parse_jwe_key_supports_prefixed_inputs():
    raw = b"1" * 32
    hex_key = "hex:" + raw.hex()
    b64_key = "b64:" + base64.b64encode(raw).decode("utf-8")

    assert parse_jwe_key(hex_key) == raw
    assert parse_jwe_key(b64_key) == raw


def test_parse_rfc3339_nanos_truncates_to_microseconds():
    value = "2020-05-28T16:26:33.162265825+08:00"

    parsed = parse_rfc3339_nanos(value)

    assert parsed.tzinfo is not None
    assert parsed.astimezone(UTC).microsecond == 162265
