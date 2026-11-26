"""协议级假 CDP 服务器：用真 WebSocket 帧跑通 cdp.py + browser.py。

为什么不用真浏览器：DSH Windows 沙箱禁止创建命名管道，Chromium 的 mojo 起不来
（`platform_channel.cc Check failed: 拒绝访问 (0x5)`），真浏览器只能在提权会话里跑。
这个假服务器复刻了浏览器在 CDP 上的最小行为：握手、JSON-RPC 应答、Fetch 请求拦截事件、
Runtime.evaluate 取值，足够验证我们的客户端与判定链路。
"""
from __future__ import annotations

import base64
import hashlib
import html as html_mod
import json
import re
import socket
import struct
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
XSS_RE = re.compile(r"window\.name='([A-Za-z0-9]{8})'")


# ---------- WebSocket 帧 ----------
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("closed")
        buf += chunk
    return buf


def _read_frame(sock: socket.socket):
    head = _recv_exact(sock, 2)
    op = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    ln = head[1] & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", _recv_exact(sock, 8))[0]
    mask = _recv_exact(sock, 4) if masked else b""
    data = _recv_exact(sock, ln) if ln else b""
    if masked:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return op, data


def _frame(payload: bytes, op: int = 0x1) -> bytes:
    head = bytearray([0x80 | op])
    n = len(payload)
    if n < 126:
        head.append(n)
    elif n < 65536:
        head.append(126)
        head += struct.pack(">H", n)
    else:
        head.append(127)
        head += struct.pack(">Q", n)
    return bytes(head) + payload


# ---------- 假网页 ----------
class FakePage:
    """决定"反射还是执行"、以及页面会不会再发子请求。

    mode:
      vuln     —— 原样反射载荷，并模拟脚本执行（写 window.name + body 属性）
      safe     —— HTML 实体编码，不执行
      reflect  —— 原样反射但**不执行**（例如 CSP 拦了内联处理器）
      redirect —— 主文档之外再请求一个站外地址（验证 Fetch 拦截器）
    """

    def __init__(self, mode: str = "vuln", foreign_url: Optional[str] = None,
                 title: str = "search"):
        self.mode = mode
        self.foreign_url = foreign_url
        self.title = title
        self.url = "about:blank"
        self.window_name = ""
        self.html = "<html><body></body></html>"
        self.started: List[str] = []
        # 页面自己会发的接口调用（harvest 的输入）。url 可以是相对路径，
        # 用导航时的 host 补全；bodies 是 requestId → getResponseBody 的应答。
        self.api_calls: List[Dict[str, Any]] = []
        self.bodies: Dict[str, Dict[str, Any]] = {}
        self.network_enabled = False

    def navigate(self, url: str) -> None:
        self.started.append(url)
        self.url = url
        q = parse_qs(urlsplit(url).query).get("q", [""])[0]
        m = XSS_RE.search(q)
        nonce = m.group(1) if m else ""
        self.window_name = ""
        if self.mode == "vuln" and nonce:
            self.window_name = nonce
            self.html = ('<html><head><title>%s</title></head>'
                         '<body data-pta-xss="%s">%s</body></html>'
                         % (self.title, nonce, q))
        elif self.mode == "reflect":
            self.html = '<html><body>%s</body></html>' % q
        else:
            self.html = '<html><body>%s</body></html>' % html_mod.escape(q)


class FakeCdpServer:
    def __init__(self, page: FakePage, path: str = "/devtools/page/FAKE"):
        self.page = page
        self.path = path
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.conn: Optional[socket.socket] = None
        self.running = True
        self.methods: List[str] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self._lock = threading.Lock()

    # --- 生命周期 ---
    def start(self) -> "FakeCdpServer":
        self.thread.start()
        return self

    def close(self) -> None:
        self.running = False
        for s in (self.conn, self.sock):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass

    def __enter__(self) -> "FakeCdpServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

    # --- 协议 ---
    def _serve(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        self.conn = conn
        req = b""
        try:
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req += chunk
            key = ""
            for line in req.decode("latin-1").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            accept = base64.b64encode(
                hashlib.sha1((key + GUID).encode()).digest()).decode()
            conn.sendall((
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
            while self.running:
                op, data = _read_frame(conn)
                if op == 0x8:
                    return
                if op != 0x1:
                    continue
                self._dispatch(json.loads(data.decode("utf-8")))
        except (EOFError, OSError, ValueError):
            return

    def _send(self, obj: Dict[str, Any]) -> None:
        with self._lock:
            if self.conn is not None:
                self.conn.sendall(_frame(json.dumps(obj).encode("utf-8")))

    def _event(self, method: str, params: Dict[str, Any], session: str = "S1") -> None:
        self._send({"method": method, "params": params, "sessionId": session})

    def _emit_network(self, url: str, session: str = "S1") -> None:
        """按真实浏览器的顺序发 Network 事件：请求 → 响应 → 完成。

        只有 `Network.enable` 过才发——客户端的 harvest 正是从 enable 开始订阅的，
        这样"没开监听就没有事件"这个真实约束也在假服务器上成立。
        """
        page = self.page
        if not page.network_enabled:
            return
        parsed = urlsplit(url)
        base = "%s://%s" % (parsed.scheme or "http", parsed.netloc or "app.test")

        def emit(rid: str, rtype: str, method: str, full: str,
                 status: int, mime: str, body: str, post: str = "",
                 headers: Optional[Dict[str, str]] = None) -> None:
            self._event("Network.requestWillBeSent", {
                "requestId": rid, "type": rtype, "frameId": "F1",
                "request": {"url": full, "method": method, "headers": headers or {},
                            **({"postData": post} if post else {})},
            }, session)
            self._event("Network.responseReceived", {
                "requestId": rid, "type": rtype,
                "response": {"status": status, "mimeType": mime, "headers": {}},
            }, session)
            self._event("Network.loadingFinished", {"requestId": rid}, session)
            page.bodies[rid] = {"body": body, "base64Encoded": False}

        emit("NET-main", "Document", "GET", url, 200, "text/html", page.html)
        for i, call in enumerate(page.api_calls):
            full = call.get("url", "")
            if full.startswith("/"):
                full = base + full
            emit("NET-api-%d" % i, call.get("type", "XHR"), call.get("method", "GET"), full,
                 int(call.get("status", 200)), call.get("mime", "application/json"),
                 call.get("body", ""), call.get("postData", ""),
                 call.get("headers"))

    def _reply(self, mid: Any, result: Optional[Dict[str, Any]] = None,
               session: Optional[str] = None) -> None:
        msg: Dict[str, Any] = {"id": mid, "result": result or {}}
        if session:
            msg["sessionId"] = session
        self._send(msg)

    def _dispatch(self, msg: Dict[str, Any]) -> None:
        method = msg.get("method", "")
        mid = msg.get("id")
        params = msg.get("params") or {}
        session = msg.get("sessionId") or "S1"
        self.methods.append(method)

        if method == "Page.navigate":
            url = params.get("url", "")
            self.page.navigate(url)
            self._emit_network(url, session)
            self._event("Fetch.requestPaused", {
                "requestId": "req-main", "frameId": "F1",
                "request": {"url": url, "method": "GET"},
            }, session)
            if self.page.mode == "redirect" and self.page.foreign_url:
                self._event("Fetch.requestPaused", {
                    "requestId": "req-foreign", "frameId": "F1",
                    "request": {"url": self.page.foreign_url, "method": "GET"},
                }, session)
            self._event("Page.loadEventFired", {}, session)
            self._reply(mid, {}, session)
            return

        if method == "Runtime.evaluate":
            expr = params.get("expression", "")
            value: Any = None
            if "outerHTML" in expr:
                value = self.page.html
            elif "location.href" in expr:
                value = self.page.url
            elif expr.strip() == "window.name":
                value = self.page.window_name
            elif expr.startswith("Boolean("):
                value = True
            self._reply(mid, {"result": {"type": "string", "value": value}}, session)
            return

        if method == "Page.captureScreenshot":
            self._reply(mid, {"data": base64.b64encode(b"\x89PNG-fake").decode()}, session)
            return

        if method in ("Fetch.continueRequest", "Fetch.failRequest",
                      "Fetch.continueResponse"):
            self._reply(mid, {}, session)
            return

        if method == "Network.enable":
            self.page.network_enabled = True
            self._reply(mid, {}, session)
            return

        if method == "Network.getResponseBody":
            rid = params.get("requestId", "")
            body = self.page.bodies.get(rid)
            if body is None:
                self._send({"id": mid, "sessionId": session,
                            "error": {"code": -32000,
                                      "message": "No resource with given identifier found"}})
                return
            self._reply(mid, body, session)
            return

        if method == "Target.createTarget":
            self._reply(mid, {"targetId": "T1"})
            return

        if method == "Target.attachToTarget":
            self._reply(mid, {"sessionId": "S1"})
            return

        # Page.enable / Runtime.enable / Log.enable / Fetch.enable / 其它
        self._reply(mid, {}, session if session != "S1" else None)
