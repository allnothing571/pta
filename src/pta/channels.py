"""通道消歧：把"被拦截"和"没有洞"分开。

问题：403 / 429 有两种成因，只看一次请求分不出来——
  1) 应用层的权限拒绝：这个身份确实不该读到这个对象，判 refuted 是对的；
  2) 拦截层（WAF / CDN / 反爬）把我们当爬虫挡了：洞可能就在那儿，
     判 refuted 就是漏报，而且是最难自查的一种漏报（报告上写着"已否定"）。

办法：同一个请求换几档"客户端身份"再发一遍。拦截层通常按 UA / Referer /
Accept 组合做白名单，而应用层的权限判定不会因为换了 UA 就放行：
  - 三档表现不一致（有的通、有的拦） → 拦截层在挑客户端（waf）
  - 三档都被拒且没有任何拦截特征     → 应用层拒绝（app_denied）
  - 三档都通                         → 没有拦截（open）

这一层只回答"这次判定能不能采信"，不回答"有没有洞"：它产出的证据只进
metrics 与 finding 的 rationale，不参与 oracle 打分（判定链一行没改）。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .probe import ProbeRequest, ProbeTool

# 这些状态码都可能来自拦截层。406/451 几乎只能是拦截层给的。
BLOCK_STATUS: Tuple[int, ...] = (403, 406, 429, 451, 503)

_CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


@dataclass(frozen=True)
class Channel:
    """一档"客户端身份"。headers 会覆盖同名默认头（不是追加）。"""
    name: str
    headers: Tuple[Tuple[str, str], ...]
    note: str


CHANNELS: Tuple[Channel, ...] = (
    Channel("plain", (), "原样：引擎自己的头（UA=pta-p0/0.1，无 Referer）"),
    Channel("browser", (
        ("User-Agent", _CHROME_UA),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Upgrade-Insecure-Requests", "1"),
    ), "浏览器：常见桌面 Chrome 的头"),
    Channel("curl", (
        ("User-Agent", "curl/8.4.0"),
        ("Accept", "*/*"),
    ), "命令行工具：很多 WAF 只拦这一类"),
)

# 拦截页正文特征。只做"是不是拦截页"的判断，不判断是哪家的规则命中。
_BODY_MARKERS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("cloudflare", re.compile(
        r"(?i)(attention required|cf-error-details|cf-chl|challenge-platform|just a moment)")),
    ("akamai", re.compile(r"(?i)(reference\s*#\s*\d|akamai reference)")),
    ("incapsula", re.compile(r"(?i)(incapsula|request unsuccessful)")),
    ("sucuri", re.compile(r"(?i)sucuri website firewall")),
    ("aws_waf", re.compile(r"(?i)(request blocked|aws waf|x-amzn-waf)")),
    ("modsecurity", re.compile(r"(?i)(mod_security|modsecurity)")),
    ("f5", re.compile(r"(?i)(the requested url was rejected|support id)")),
    ("fortiweb", re.compile(r"(?i)(fortiweb|blocked by web application firewall)")),
    ("challenge", re.compile(r"(?i)(captcha|verify you are human|安全验证|人机验证|请稍候)")),
)

# 拦截层常留的响应头。正文可能被定制成普通 403 页，头往往还留着。
_HEADER_MARKERS: Dict[str, str] = {
    "cf-ray": "cloudflare",
    "cf-cache-status": "cloudflare",
    "cf-mitigated": "cloudflare",
    "x-sucuri-id": "sucuri",
    "x-sucuri-block": "sucuri",
    "x-iinfo": "incapsula",
    "x-amzn-requestid": "aws_waf",
    "x-amzn-waf-action": "aws_waf",
    "x-amz-cf-id": "cloudfront",
    "akamai-grn": "akamai",
    "x-mod-security": "modsecurity",
    "x-protected-by": "generic_waf",
}

_MAX_TEXT = 64 * 1024


@dataclass
class ChannelResult:
    name: str
    status: int = 0
    blocked: bool = False
    markers: List[str] = field(default_factory=list)
    evidence_id: Optional[str] = None
    body_len: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.status) and not self.blocked

    def to_json(self) -> Dict[str, Any]:
        return {
            "name": self.name, "status": self.status, "blocked": self.blocked,
            "ok": self.ok, "markers": list(self.markers),
            "evidence_id": self.evidence_id, "body_len": self.body_len,
            "error": self.error,
        }


@dataclass
class ChannelReport:
    url: str
    results: List[ChannelResult] = field(default_factory=list)
    requests: int = 0

    @property
    def usable(self) -> List[str]:
        return [r.name for r in self.results if r.ok]

    @property
    def blocked_names(self) -> List[str]:
        return [r.name for r in self.results if r.blocked]

    @property
    def best(self) -> Optional[str]:
        # 优先原样通道：能不换身份就不换，换得越多越偏离"真实用户"。
        for name in ("plain", "browser", "curl"):
            if name in self.usable:
                return name
        return self.usable[0] if self.usable else None

    @property
    def verdict(self) -> str:
        if not self.results:
            return "unreachable"
        ok = self.usable
        blocked = [r for r in self.results if r.blocked]
        if ok and blocked:
            return "waf"
        if ok:
            return "open"
        if blocked:
            # 全都拦，但一丁点拦截特征都没有 → 更像应用层的统一拒绝页
            return "waf" if any(r.markers for r in blocked) else "app_denied"
        return "unreachable"

    @property
    def markers(self) -> List[str]:
        out: List[str] = []
        for r in self.results:
            for m in r.markers:
                if m not in out:
                    out.append(m)
        return out

    @property
    def evidence_ids(self) -> List[str]:
        return [r.evidence_id for r in self.results if r.evidence_id]

    def channel(self, name: Optional[str]) -> Optional[ChannelResult]:
        for r in self.results:
            if r.name == name:
                return r
        return None

    def to_json(self) -> Dict[str, Any]:
        return {
            "url": self.url, "verdict": self.verdict, "best": self.best,
            "usable": self.usable, "blocked": self.blocked_names,
            "markers": self.markers, "requests": self.requests,
            "channels": [r.to_json() for r in self.results],
        }


class ChannelProbe:
    """同一个请求跑几档客户端身份，回答"这次被拦是不是因为我们自己太显眼"。

    只发不带载荷的请求（level 默认 L1），除非调用方显式传 payload_class——
    那时发的是"带载荷的同一条请求"，用来判断"基线能过、载荷过不去"是不是规则命中。
    """

    def __init__(self, probe: ProbeTool, channels: Sequence[Channel] = CHANNELS):
        self.probe = probe
        self.channels = tuple(channels)

    def run(self, url: str, identity: str = "none", method: str = "GET",
            param_path: Optional[str] = None, payload_class: Optional[str] = None,
            payload_variant: Optional[str] = None, level: Optional[str] = None,
            sample: int = 1, timeout_s: Optional[float] = None,
            extra_headers: Tuple[Tuple[str, str], ...] = (),
            id_plus_one: Optional[str] = None) -> ChannelReport:
        report = ChannelReport(url=url)
        for ch in self.channels:
            result = self._one(ch, url, identity, method, param_path, payload_class,
                               payload_variant, level, sample, timeout_s, extra_headers,
                               id_plus_one)
            report.requests += 1
            report.results.append(result)
            # 原样档就通 → 根本没有拦截，不必再花两次请求确认
            if result.name == "plain" and result.ok:
                break
            # 已经能定性（有一档通、有一档拦）就不再花预算试剩下的：
            # 多试一档改变不了"拦截层在挑客户端"这个结论。
            if report.usable and report.blocked_names:
                break
        return report

    # ---------- 内部 ----------
    def _one(self, ch: Channel, url: str, identity: str, method: str,
             param_path: Optional[str], payload_class: Optional[str],
             payload_variant: Optional[str], level: Optional[str], sample: int,
             timeout_s: Optional[float],
             extra_headers: Tuple[Tuple[str, str], ...],
             id_plus_one: Optional[str] = None) -> ChannelResult:
        headers = tuple(extra_headers) + tuple(ch.headers)
        res = self.probe.run(ProbeRequest(
            action_id="channel:%s" % ch.name,
            url=url,
            method=method,
            identity=identity,
            label="channel",
            param_path=param_path,
            payload_class=payload_class,
            payload_variant=payload_variant,
            sample=max(1, int(sample)),
            headers_extra=headers,
            level=level or "L1",
            timeout_s=timeout_s or 10.0,
            id_plus_one=id_plus_one,
        ))
        if res.status != "ok" or res.extract is None:
            return ChannelResult(name=ch.name,
                                 error="%s%s" % (res.status, (":" + res.reason) if res.reason else ""))
        ext = res.extract
        markers = self._markers(ext.body_sha256, ext.evidence_id)
        return ChannelResult(
            name=ch.name,
            status=int(ext.status),
            blocked=int(ext.status) in BLOCK_STATUS,
            markers=markers,
            evidence_id=ext.evidence_id,
            body_len=int(ext.body_len),
        )

    def _markers(self, body_sha256: str, evidence_id: str) -> List[str]:
        out: List[str] = []
        text = self._text(body_sha256)
        for name, pat in _BODY_MARKERS:
            if pat.search(text):
                out.append(name)
        for key, vendor in self._headers(evidence_id).items():
            if key in _HEADER_MARKERS and _HEADER_MARKERS[key] not in out:
                out.append(_HEADER_MARKERS[key])
        return out

    def _text(self, body_sha256: str) -> str:
        try:
            body = self.probe.cas.get(body_sha256)
        except Exception:  # noqa: BLE001 - 取不到正文只影响特征匹配，不该中断判定
            return ""
        return body[:_MAX_TEXT].decode("utf-8", "replace")

    def _headers(self, evidence_id: str) -> Dict[str, str]:
        try:
            row = self.probe.store.get_evidence_row(evidence_id)
        except Exception:  # noqa: BLE001
            return {}
        if row is None:
            return {}
        try:
            data = json.loads(row["headers_json"] or "{}")
        except (ValueError, TypeError):
            return {}
        # evidence.headers_json 存的是 [[name, value], ...]（保留原始顺序与重复项），
        # 也兼容 dict 形态；这里只关心"有没有这个头"和它的值。
        if isinstance(data, dict):
            return {str(k).lower(): str(v) for k, v in data.items()}
        if isinstance(data, (list, tuple)):
            out: Dict[str, str] = {}
            for item in data:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    out.setdefault(str(item[0]).lower(), str(item[1]))
            return out
        return {}
