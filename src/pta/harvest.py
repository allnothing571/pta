"""把一次浏览器导航里**页面自己发出**的请求收下来。

为什么需要这一层：现在引擎只会发"我构造的请求"，所以接口参数只能靠猜
（`name_hint="id|q|search"`）。真实应用的接口长什么样，页面里的脚本最清楚：
它已经替我们写出了 `POST /api/v2/profile {"displayName": "...", "role": "user"}`。
问题只是没人把它记下来。

这一层只回答一个问题：**这个页面在浏览过程中，主动发过哪些请求？**
它不判漏洞、不构造载荷、不改判定链——产出的证据 label 统一为 `harvest`，
只交给 Planner 当"参数从哪来"的线索。

三条刻意的取舍：

1. **只认同源主机的请求。** 跨站的子请求是第三方资产（CDN、埋点、字体），
   既不在授权范围内，也不该进证据库。这跟 Fetch 拦截器的越界判定是两套逻辑：
   拦截器管"能不能发"，这里管"发了的哪条值得记"。
2. **按"形状"去重。** `(method, path, 参数名集合, body 字段集合)` 相同即同一条。
   同一屏可能发十次 `GET /api/items?page=1&size=20`，记十遍没有信息增量；
   但 `?page=` 与 `?q=` 形状不同，必须各记一条——它们指向不同的参数。
3. **响应正文按需取。** CDP 的 `Network.getResponseBody` 是逐条 RPC，取全文很贵；
   只取 `XHR`/`Fetch`/`Document` 且**已完成**的，且有上限（`limit`）。取不到正文
   不算失败：这条调用照样入库，只是 `body_len=0`，仍然贡献参数名。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

# 值得取正文的资源类型。图片/字体/样式表只有字节数有意义，参数在 URL 里已经拿到了。
BODY_TYPES = ("XHR", "Fetch", "Document")
# 体积上限：超过就只记形状。2MB 足够放下一个列表接口，又不至于把 CAS 灌满。
MAX_BODY_BYTES = 2 * 1024 * 1024


@dataclass
class Call:
    """页面发出的一条请求。字段全部可序列化，不含 Cookie/Authorization 的值。"""

    request_id: str
    method: str
    url: str
    resource_type: str = "Other"
    status: int = 0
    mime: str = ""
    post_data: str = ""
    finished: bool = False
    error: str = ""

    # ---------- 形状 ----------
    def parts(self) -> Tuple[str, str, int, str]:
        parsed = urlsplit(self.url)
        scheme = parsed.scheme or "http"
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, port, parsed.path or "/"

    def query_names(self) -> Tuple[str, ...]:
        """只留参数名，不留值——值可能是会话 token 或个人信息。"""
        names = [k for k, _ in parse_qsl(urlsplit(self.url).query, keep_blank_values=True)]
        return tuple(sorted(set(names)))

    def body_fields(self) -> Tuple[str, ...]:
        raw = (self.post_data or "").strip()
        if not raw:
            return ()
        if raw[:1] in ("{", "["):
            try:
                obj = json.loads(raw)
            except ValueError:
                return ()
            if isinstance(obj, dict):
                return tuple(sorted(str(k) for k in obj.keys()))
            return ()
        # form-urlencoded
        return tuple(sorted(set(k for k, _ in parse_qsl(raw, keep_blank_values=True))))

    def shape(self) -> Tuple[str, str, Tuple[str, ...], Tuple[str, ...]]:
        _, _, _, path = self.parts()
        return (self.method.upper(), path, self.query_names(), self.body_fields())

    def to_json(self) -> Dict[str, Any]:
        scheme, host, port, path = self.parts()
        return {
            "method": self.method.upper(), "url": self.url, "scheme": scheme,
            "host": host, "port": port, "path": path,
            "query_names": list(self.query_names()), "body_fields": list(self.body_fields()),
            "resource_type": self.resource_type, "status": self.status, "mime": self.mime,
            "has_request_body": bool(self.post_data),
            "finished": self.finished, "error": self.error,
        }


class Harvester:
    """订阅 CDP 的 Network 事件，攒出本次导航的调用列表。

    用法：由 `BrowserTool` 在 `_on_cdp_event` 里转发 `Network.*`，导航结束后
    调 `calls()` 取去重结果。它自己不发任何 CDP 命令——取正文由调用方决定，
    因为那需要 pump 事件循环，不能在事件回调里做（会重入）。
    """

    def __init__(self, allowed_hosts: Tuple[str, ...] = (), limit: int = 24):
        self.allowed_hosts = tuple(h.lower() for h in allowed_hosts)
        self.limit = max(limit, 1)
        self._calls: Dict[str, Call] = {}
        self._order: List[str] = []
        self.skipped_cross_origin = 0
        self.skipped_type = 0

    # ---------- 事件 ----------
    def on_event(self, method: str, params: Dict[str, Any]) -> None:
        if method == "Network.requestWillBeSent":
            self._on_request(params)
        elif method == "Network.responseReceived":
            self._on_response(params)
        elif method in ("Network.loadingFinished", "Network.loadingFailed"):
            call = self._calls.get(str(params.get("requestId", "")))
            if call is not None:
                call.finished = True
                if method == "Network.loadingFailed":
                    call.error = str(params.get("errorText", ""))[:200]

    def _on_request(self, params: Dict[str, Any]) -> None:
        req = params.get("request", {}) or {}
        url = str(req.get("url", ""))
        if not url or url.startswith(("data:", "about:", "blob:", "chrome:", "devtools:", "ws:", "wss:")):
            return
        rtype = str(params.get("type", "Other"))
        if rtype not in BODY_TYPES:
            self.skipped_type += 1
            return
        host = (urlsplit(url).hostname or "").lower()
        if self.allowed_hosts and host not in self.allowed_hosts:
            # 第三方资产：不在授权范围，也不该进证据库。
            self.skipped_cross_origin += 1
            return
        rid = str(params.get("requestId", ""))
        if not rid:
            return
        call = Call(request_id=rid, method=str(req.get("method", "GET")).upper(),
                    url=url, resource_type=rtype,
                    post_data=str(req.get("postData", "") or ""))
        if rid not in self._calls:
            self._order.append(rid)
        self._calls[rid] = call

    def _on_response(self, params: Dict[str, Any]) -> None:
        call = self._calls.get(str(params.get("requestId", "")))
        if call is None:
            return
        resp = params.get("response", {}) or {}
        try:
            call.status = int(resp.get("status", 0) or 0)
        except (TypeError, ValueError):
            call.status = 0
        call.mime = str(resp.get("mimeType", "") or "")[:120]

    # ---------- 取用 ----------
    def calls(self) -> List[Call]:
        """按首次出现顺序，按形状去重，截到上限。"""
        seen = set()
        out: List[Call] = []
        for rid in self._order:
            call = self._calls.get(rid)
            if call is None:
                continue
            key = call.shape()
            if key in seen:
                continue
            seen.add(key)
            out.append(call)
            if len(out) >= self.limit:
                break
        return out

    def body_requests(self, calls: List[Call]) -> List[Call]:
        """值得单独去取正文的那些（按 shape 已去重，body 可选的除外）。"""
        out = []
        for call in calls:
            if call.resource_type not in BODY_TYPES:
                continue
            if not call.finished or call.error:
                continue
            out.append(call)
        return out

    def stats(self) -> Dict[str, Any]:
        return {"seen": len(self._order), "kept": len(self.calls()),
                "skipped_type": self.skipped_type,
                "skipped_cross_origin": self.skipped_cross_origin}


def decode_body(result: Dict[str, Any]) -> Optional[bytes]:
    """`Network.getResponseBody` 的应答 → 原始字节。取不到就返回 None。"""
    if not isinstance(result, dict):
        return None
    body = result.get("body")
    if body is None:
        return None
    if result.get("base64Encoded"):
        import base64
        try:
            return base64.b64decode(str(body))
        except Exception:
            return None
    return str(body).encode("utf-8", "replace")
