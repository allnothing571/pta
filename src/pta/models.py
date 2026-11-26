"""证据层的数据模型。

设计要点：
1. 请求指纹决定 evidence_id，时间不参与。
2. 秘密值不落盘，只存 vault 引用与哈希。
3. 模型只能看到 Extract，看不到原始字节。
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

# 只纳入这些头参与请求指纹，避免 UA 等噪声制造重复证据。
HEADER_FP_ALLOW = frozenset(
    {"accept", "content-type", "x-requested-with", "authorization", "cookie", "origin"}
)
SECRET_HEADERS = frozenset(
    {"authorization", "cookie", "x-api-key", "x-csrf-token", "proxy-authorization"}
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_query(pairs: Sequence[Tuple[str, str]]) -> str:
    return "&".join("%s=%s" % (k, v) for k, v in pairs)


@dataclass(frozen=True)
class Header:
    """一个请求头。kind=vault_ref 时 value 为 None，只保留 ref 与哈希。"""

    name: str
    kind: str = "literal"  # literal | vault_ref | derived
    value: Optional[str] = None
    ref: Optional[str] = None
    derive: Optional[str] = None
    value_sha256: Optional[str] = None

    def persisted(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"name": self.name, "kind": self.kind}
        if self.kind == "literal" and self.value is not None:
            out["value"] = self.value
        if self.ref:
            out["ref"] = self.ref
        if self.derive:
            out["derive"] = self.derive
        if self.value_sha256:
            out["value_sha256"] = self.value_sha256
        return out

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "Header":
        return Header(
            name=d["name"],
            kind=d.get("kind", "literal"),
            value=d.get("value"),
            ref=d.get("ref"),
            derive=d.get("derive"),
            value_sha256=d.get("value_sha256"),
        )


@dataclass(frozen=True)
class Body:
    kind: str = "none"  # none | json | form | raw
    sha256: Optional[str] = None
    blob: Optional[str] = None
    length: int = 0


@dataclass(frozen=True)
class CanonicalRequest:
    """规范化请求。所有字段都可序列化，秘密值不在其中。"""

    engagement_id: str
    method: str
    scheme: str
    host: str
    port: int
    raw_path: str
    query: Tuple[Tuple[str, str], ...] = ()
    headers: Tuple[Header, ...] = ()
    body: Body = field(default_factory=Body)
    identity: str = "none"
    asset_node_id: Optional[str] = None
    param_path: Optional[str] = None
    payload_class: Optional[str] = None
    payload_variant: Optional[str] = None
    side_effect_level: str = "L1"

    def url(self) -> str:
        q = canonical_query(self.query)
        return "%s://%s:%d%s%s" % (
            self.scheme,
            self.host,
            self.port,
            self.raw_path,
            ("?" + q) if q else "",
        )

    def to_json(self) -> Dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "method": self.method,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "raw_path": self.raw_path,
            "query": [list(p) for p in self.query],
            "headers": [h.persisted() for h in self.headers],
            "body": {
                "kind": self.body.kind,
                "sha256": self.body.sha256,
                "blob": self.body.blob,
                "length": self.body.length,
            },
            "identity": self.identity,
            "asset_node_id": self.asset_node_id,
            "param_path": self.param_path,
            "payload_class": self.payload_class,
            "payload_variant": self.payload_variant,
            "side_effect_level": self.side_effect_level,
        }

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "CanonicalRequest":
        return CanonicalRequest(
            engagement_id=d["engagement_id"],
            method=d["method"],
            scheme=d["scheme"],
            host=d["host"],
            port=int(d["port"]),
            raw_path=d["raw_path"],
            query=tuple((str(a), str(b)) for a, b in d.get("query", [])),
            headers=tuple(Header.from_json(h) for h in d.get("headers", [])),
            body=Body(
                kind=d["body"]["kind"],
                sha256=d["body"]["sha256"],
                blob=d["body"]["blob"],
                length=int(d["body"].get("length", 0)),
            ),
            identity=d.get("identity", "none"),
            asset_node_id=d.get("asset_node_id"),
            param_path=d.get("param_path"),
            payload_class=d.get("payload_class"),
            payload_variant=d.get("payload_variant"),
            side_effect_level=d.get("side_effect_level", "L1"),
        )


@dataclass(frozen=True)
class ResolvedRequest:
    """已填充真实值、可作为 socket 输入的请求。只在内存中存在。"""

    method: str
    scheme: str
    host: str
    port: int
    raw_path: str
    query: Tuple[Tuple[str, str], ...]
    headers: Tuple[Tuple[str, str], ...]
    body: bytes
    pinned_ip: str = ""

    def target(self) -> str:
        q = canonical_query(self.query)
        return "%s://%s:%d%s%s" % (
            self.scheme,
            self.host,
            self.port,
            self.raw_path,
            ("?" + q) if q else "",
        )


@dataclass(frozen=True)
class RawResponse:
    status: int
    reason: str
    http_version: str
    headers: Tuple[Tuple[str, str], ...]
    body: bytes
    t_send: float
    t_first_byte: float
    t_end: float
    server_timing: Optional[Dict[str, float]] = None

    def header(self, name: str) -> Optional[str]:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def total_ms(self) -> float:
        return (self.t_end - self.t_send) * 1000.0


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    engagement_id: str
    label: str
    identity: str
    request: CanonicalRequest
    status: int
    content_type: Optional[str]
    body_sha256: str
    body_len: int
    headers: Tuple[Tuple[str, str], ...]
    sample_count: int
    timings_ms: Tuple[float, ...]
    ts_first: str
    ts_last: str
    request_blob: str = ""


@dataclass(frozen=True)
class Extract:
    """给模型/UI 看的脱敏视图。永远不含原始字节。"""

    evidence_id: str
    label: str
    identity: str
    method: str
    url: str
    status: int
    content_type: Optional[str]
    body_len: int
    body_sha256: str
    sample_count: int
    total_ms_last: float
    preview: str
    headers: Dict[str, str]

    def to_json(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "label": self.label,
            "identity": self.identity,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "content_type": self.content_type,
            "body_len": self.body_len,
            "body_sha256": self.body_sha256,
            "sample_count": self.sample_count,
            "total_ms_last": round(self.total_ms_last, 1),
            "preview": self.preview,
            "headers": self.headers,
        }


@dataclass(frozen=True)
class Verdict:
    passed: bool
    confidence: float
    metrics: Dict[str, Any]
    rationale: str
    missing_evidence: Tuple[str, ...] = ()
    # 有的模板靠正特征堆分（比如"敏感文件"同时认 passwd、目录列表、堆栈），
    # 结论确认后到底命中的是哪一类，只有 oracle 自己知道。留一个空位给它改标题，
    # 否则报告上会出现"凭据文件暴露"其实命中的是 Java 堆栈这种张冠李戴。
    title: str = ""

    def to_json(self) -> Dict[str, Any]:
        out = {
            "passed": self.passed,
            "confidence": round(self.confidence, 4),
            "metrics": self.metrics,
            "rationale": self.rationale,
            "missing_evidence": list(self.missing_evidence),
        }
        if self.title:
            out["title"] = self.title
        return out


def verdict_status(confidence: float) -> str:
    if confidence >= 0.85:
        return "confirmed"
    if confidence >= 0.60:
        return "hypothesis"
    return "refuted"


_DYNAMIC_PATTERNS = (
    re.compile(rb"[0-9a-f]{32}"),
    re.compile(rb"\b\d{13}\b"),
    re.compile(rb"(?i)csrf[-_]?\w+"),
    re.compile(rb'"timestamp"\s*:\s*"?[^",}]+'),
)

_MASK = (re.compile(rb"sk-[A-Za-z0-9_-]{8,}"), re.compile(rb"(?i)bearer\s+[A-Za-z0-9._~+/=-]{12,}"))


def preview_text(body: bytes, limit: int = 512) -> str:
    head = body[:limit]
    for pat in _MASK:
        head = pat.sub(b"[REDACTED]", head)
    try:
        return head.decode("utf-8", "replace")
    except Exception:  # pragma: no cover
        return repr(head[:limit])


def redact_bytes(body: bytes) -> bytes:
    """整段脱敏：给报告导出用（预览只截前 512 字节，导出要覆盖全文）。"""
    out = body
    for pat in _MASK:
        out = pat.sub(b"[REDACTED]", out)
    return out


def strip_dynamic(body: bytes) -> bytes:
    out = body
    for pat in _DYNAMIC_PATTERNS:
        out = pat.sub(b"<dyn>", out)
    return out
