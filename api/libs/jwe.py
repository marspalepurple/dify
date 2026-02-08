"""用于解码直连对称密钥 JWE 紧凑序列化的工具函数。"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from Crypto.Cipher import AES

logger = logging.getLogger(__name__)

_COMPACT_JWE_PARTS = 5
_NANOSECONDS_PATTERN = re.compile(
    r"^(?P<main>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)


class JweDecodeError(ValueError):
    """当 JWE 令牌无法解码时抛出。"""


@dataclass(frozen=True)
class JwePayload:
    """包含头信息的 JWE 解码载荷。"""

    header: dict[str, str]
    plaintext: dict[str, object]


def decode_compact_jwe(token: str, key: bytes) -> JwePayload:
    """
    使用直连对称密钥（alg=dir，enc=A256GCM）解码紧凑 JWE 令牌。

    :param token: 紧凑序列化的 JWE 令牌。
    :param key: 内容加密密钥的原始字节（A256GCM 需要 32 字节）。
    :return: 解码后的 JWE 载荷。
    :raises JweDecodeError: 令牌非法或算法不受支持时抛出。
    """
    parts = token.split(".")
    if len(parts) != _COMPACT_JWE_PARTS:
        raise JweDecodeError("Invalid JWE compact serialization.")

    header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts
    try:
        header = json.loads(_base64url_decode(header_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JweDecodeError("Invalid JWE header.") from exc

    if header.get("alg") != "dir":
        raise JweDecodeError("Unsupported JWE alg; expected 'dir'.")
    if header.get("enc") != "A256GCM":
        raise JweDecodeError("Unsupported JWE enc; expected 'A256GCM'.")

    if encrypted_key_b64 not in {"", None}:
        logger.debug("直连 JWE 模式忽略加密密钥字段。")

    if len(key) != 32:
        raise JweDecodeError("Invalid JWE key length for A256GCM.")

    iv = _base64url_decode(iv_b64)
    ciphertext = _base64url_decode(ciphertext_b64)
    tag = _base64url_decode(tag_b64)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(header_b64.encode("utf-8"))
    try:
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise JweDecodeError("Failed to decrypt JWE payload.") from exc

    try:
        plaintext = json.loads(plaintext_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JweDecodeError("Invalid JWE payload JSON.") from exc

    return JwePayload(header=header, plaintext=plaintext)


def parse_jwe_key(raw_key: str) -> bytes:
    """
    将 JWE 密钥字符串解析为原始字节。

    支持格式：
    - "hex:<hexstring>"
    - "base64:<standard base64>"
    - "b64:<standard base64>"
    - 直接 base64url / base64 字符串
    - 32 字符 ASCII 明文密钥（按 UTF-8 转字节）
    """
    if raw_key.startswith("hex:"):
        return bytes.fromhex(raw_key.removeprefix("hex:"))
    if raw_key.startswith(("base64:", "b64:")):
        return base64.b64decode(raw_key.split(":", 1)[1])

    for decoder in (_base64url_decode, _base64_decode_padded):
        try:
            decoded = decoder(raw_key)
        except Exception:
            continue
        if decoded:
            return decoded

    if len(raw_key) == 32:
        return raw_key.encode("utf-8")

    raise JweDecodeError("Unsupported JWE key format.")


def parse_rfc3339_nanos(value: str) -> datetime:
    """
    解析包含可选纳秒精度的 RFC3339 时间戳。
    """
    match = _NANOSECONDS_PATTERN.match(value)
    if not match:
        raise ValueError("Invalid RFC3339 timestamp.")

    main = match.group("main")
    fraction = match.group("fraction") or ""
    tz = match.group("tz") or ""

    if tz == "Z":
        tz = "+00:00"

    if fraction:
        fraction = (fraction[:6]).ljust(6, "0")
        formatted = f"{main}.{fraction}{tz}"
    else:
        formatted = f"{main}{tz}"

    parsed = datetime.fromisoformat(formatted)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _base64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _base64_decode_padded(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.b64decode(data + padding)
