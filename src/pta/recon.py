"""侦察层：把一个种子 URL 变成一张 Planner 能用的资产表。

为什么要单独一层：在执行器眼里，"世界"只有 `store` 里已经发出的请求。
没有这一层，`auto` 就只能验证你手工喂进来的 URL+参数——它是验证器，不是挖掘器。
这一层做的事很窄：只发 L1 GET，把 HTML 里的链接/表单/脚本、JS 里的接口路径
抽出来，再排队抓下一层。每抓一页都会落一条证据（带 query 参数），
`PlannerState.collect()` 因此能自动看见这些端点。

设计约束（与五条不变量对齐）：
- 每个 URL 都过 `scope.check_request()`（域名/端口/私网/deny_paths 全在那一处），
  越界只记 skipped，绝不发出去；
- 走 `ProbeTool`，所以预算、DNS pin、出口代理、证据入库全部复用同一套；
- 只 GET、不带载荷、不改数据 —— 侦察永远是 L1；
- 同源限制默认打开（链接到外部域名一律不抓，避免变成全网爬虫）。
"""
from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .errors import ScopeViolation
from .probe import ProbeRequest
from .scope import check_request

# 只抓这些后缀的页面；二进制/图片直接跳过，不浪费预算
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
             ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip",
             ".pdf", ".exe", ".dmg", ".iso")

# JS 里像接口路径的字符串：以 / 开头、或整条 URL；排除明显是资源的
_JS_PATH = re.compile(r"""["'`]((?:https?://[^"'`\s<>]{4,200})|(?:/[^"'`\s<>]{1,200}))["'`]""")

_TAG_PARAM = ("input", "select", "textarea", "button")


class _DocParser(HTMLParser):
    """只抽四种东西：链接、脚本、表单、表单字段名。

    不做 DOM 树、不写选择器——侦察层要的是"下一个 URL"和"参数名"，
    完整 DOM 交给浏览器那一层（`browser.py`）。
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.inline_js: List[str] = []
        self._form: Optional[Dict[str, Any]] = None
        self._in_script = False
        self._buf: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:                       # 行内脚本单独攒，不跟 href 混在一起
                self._in_script = True
                self._buf = []
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                          "params": []}
        elif tag in _TAG_PARAM and self._form is not None and a.get("name"):
            if a["name"] not in self._form["params"]:
                self._form["params"].append(a["name"])

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self.inline_js.append("".join(self._buf))
            self._in_script = False
            self._buf = []
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def close(self) -> None:      # 表单/脚本没闭合也要收
        super().close()
        if self._in_script:
            self.inline_js.append("".join(self._buf))
            self._in_script = False
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


@dataclass
class Form:
    action: str
    method: str
    params: Tuple[str, ...]

    def to_json(self) -> Dict[str, Any]:
        return {"action": self.action, "method": self.method, "params": list(self.params)}


@dataclass
class Page:
    url: str
    status: int
    content_type: str
    depth: int
    links: Tuple[str, ...] = ()
    scripts: Tuple[str, ...] = ()
    forms: Tuple[Form, ...] = ()
    endpoints: Tuple[str, ...] = ()      # 从 JS 里抽出来的接口路径
    evidence_id: str = ""
    # 跟完重定向之后真正落地的地址（没跳就是空）。302 到 /login 时全靠它说清楚。
    final_url: str = ""

    def to_json(self) -> Dict[str, Any]:
        return {"url": self.url, "status": self.status, "content_type": self.content_type,
                "depth": self.depth, "links": list(self.links), "scripts": list(self.scripts),
                "forms": [f.to_json() for f in self.forms],
                "endpoints": list(self.endpoints), "evidence_id": self.evidence_id,
                "final_url": self.final_url}


@dataclass
class ReconReport:
    seeds: Tuple[str, ...]
    pages: List[Page] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    requests: int = 0
    # 站点自己跳到范围外的那几跳（最常见：跳到未授权端口），
    # 是"为什么只抓到 302"的答案。
    blocked_redirects: List[Dict[str, str]] = field(default_factory=list)

    def urls(self) -> List[str]:
        return [p.url for p in self.pages]

    def endpoints(self) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        for p in self.pages:
            for e in p.endpoints:
                if e not in seen:
                    seen.add(e)
                    out.append(e)
        return out

    def params(self) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        for p in self.pages:
            for k in _query_keys(p.url):
                if k not in seen:
                    seen.add(k)
                    out.append(k)
            for f in p.forms:
                for k in f.params:
                    if k not in seen:
                        seen.add(k)
                        out.append(k)
        return out

    def to_json(self) -> Dict[str, Any]:
        return {"seeds": list(self.seeds), "requests": self.requests,
                "pages": [p.to_json() for p in self.pages],
                "endpoints": self.endpoints(), "params": self.params(),
                "skipped": self.skipped,
                "blocked_redirects": list(self.blocked_redirects),
                "counts": {"pages": len(self.pages), "endpoints": len(self.endpoints()),
                           "params": len(self.params()), "skipped": len(self.skipped),
                           "blocked_redirects": len(self.blocked_redirects)}}


def _query_keys(url: str) -> List[str]:
    return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


def _norm(url: str, base: Optional[str] = None) -> str:
    """统一成 scheme://host[:port]/path?query，去掉 fragment（同一资源不重复抓）。"""
    if base:
        url = urljoin(base, url)
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        return ""
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _looks_static(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(_SKIP_EXT)


def _js_endpoints(text: str) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for m in _JS_PATH.finditer(text):
        cand = m.group(1).replace("\\/", "/")
        if cand.startswith("//") or cand.startswith("#"):
            continue
        if not (cand.startswith("/") or cand.startswith("http")):
            continue
        if _looks_static(cand):
            continue
        if cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
    return out


class Recon:
    """BFS 抓取。`max_pages` 是硬上限，预算耗尽时也会提前停。"""

    def __init__(self, ws, max_pages: int = 25, max_depth: int = 2, identity: str = "none",
                 parse_js: bool = True, same_origin: bool = True,
                 follow_redirects: bool = True, max_bytes: int = 2 * 1024 * 1024):
        self.ws = ws
        self.max_pages = max(0, int(max_pages))
        self.max_depth = max(0, int(max_depth))
        self.identity = identity
        self.parse_js = parse_js
        self.same_origin = same_origin
        self.follow_redirects = follow_redirects
        self.max_bytes = max_bytes

    # ---------- 入口 ----------
    def run(self, seeds: Iterable[str]) -> ReconReport:
        norm_seeds: List[str] = []
        for s in seeds:
            n = _norm(s)
            if n and n not in norm_seeds:
                norm_seeds.append(n)
        report = ReconReport(seeds=tuple(norm_seeds))
        if not norm_seeds:
            return report

        hosts = {urlsplit(u).netloc for u in norm_seeds}
        queue: Deque[Tuple[str, int]] = deque((u, 0) for u in norm_seeds)
        seen: Set[str] = set()

        while queue and len(report.pages) < self.max_pages:
            if self.ws.budget.used >= self.ws.budget.max_requests:
                report.skipped.append({"url": queue[0][0], "reason": "budget_exhausted"})
                break
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)

            if _looks_static(url):
                report.skipped.append({"url": url, "reason": "static_asset"})
                continue
            try:                                  # 越界只记一笔，绝不发出去
                check_request(self.ws.scope, "GET", url, "L1")
            except ScopeViolation as exc:
                report.skipped.append({"url": url, "reason": "scope: %s" % exc})
                continue

            page = self._fetch(url, depth, report)
            report.requests += 1
            if page is None:
                report.skipped.append({"url": url, "reason": "fetch_failed"})
                continue
            report.pages.append(page)

            if depth >= self.max_depth:
                continue
            nxt: List[Tuple[str, int]] = []
            for link in list(page.links) + list(page.scripts):
                n = _norm(link, base=url)
                if not n or n in seen:
                    continue
                if self.same_origin and urlsplit(n).netloc not in hosts:
                    report.skipped.append({"url": n, "reason": "cross_origin"})
                    continue
                nxt.append((n, depth + 1))
            # 链接先进队列尾部，深度优先会让首批种子能更快铺开
            queue.extend(nxt)
        return report

    # ---------- 单页 ----------
    def _fetch(self, url: str, depth: int,
               report: Optional[ReconReport] = None) -> Optional[Page]:
        res = self.ws.probe.run(ProbeRequest(
            action_id="recon-%d" % (len(self.ws.store.list_evidence(self.ws.scope.engagement_id)) + 1),
            url=url, method="GET", identity=self.identity, label="recon", level="L1",
            follow_redirects=self.follow_redirects,
        ))
        if report is not None and res.redirect_blocked:
            target, _, why = res.redirect_blocked.partition("|")
            # 只有 seed 自己没跟成才算"停在这儿"；页面上的某个链接跟不过去是常态，
            # 记下来但不该冒充停下来的原因。
            report.blocked_redirects.append({"url": url, "target": target, "reason": why,
                                             "seed": _norm(url) in report.seeds})
        if res.status != "ok" or res.extract is None:
            return None
        ext = res.extract
        ctype = (ext.content_type or "").lower()
        page = Page(url=url, status=ext.status, content_type=ctype, depth=depth,
                    evidence_id=ext.evidence_id or "",
                    final_url=(res.redirects[-1] if res.redirects else ""))

        if ext.body_len > self.max_bytes:
            return page
        try:
            body = self.ws.cas.get(ext.body_sha256)
        except Exception:                 # 证据体不在 CAS（外部导入/被清理），只留元信息
            return page
        text = _decode(body)

        if "html" in ctype or "xml" in ctype:
            parser = _DocParser()
            try:
                parser.feed(text)
                parser.close()
            except Exception:
                pass
            page.links = tuple(dict.fromkeys(parser.links))
            page.scripts = tuple(dict.fromkeys(parser.scripts))
            page.forms = tuple(Form(action=f["action"], method=f["method"],
                                    params=tuple(f["params"])) for f in parser.forms)
            # 行内脚本也扫一遍：单页应用把接口写死在 <script> 里
            if self.parse_js and parser.inline_js:
                page.endpoints = tuple(_js_endpoints("\n".join(parser.inline_js)))
        elif "javascript" in ctype and self.parse_js:
            page.endpoints = tuple(_js_endpoints(text))
        return page


def _decode(body: bytes) -> str:
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return body.decode(enc, errors="ignore")
        except LookupError:
            continue
    return ""


def write_report(ws, report: ReconReport, name: str = "recon.json") -> str:
    """落到工作区根目录，给操作者与下一次运行看；不进 CAS（它不是证据）。"""
    import os
    path = os.path.join(ws.root, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_json(), fh, ensure_ascii=False, indent=2)
    return path
