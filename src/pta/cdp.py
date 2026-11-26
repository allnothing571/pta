"""最小 CDP/WebSocket 客户端（Python 3.8 标准库）。

只依赖 stdlib：socket + hashlib + base64 + json。
Chrome/Edge 的 DevTools 协议是文本帧 JSON-RPC，握手用 RFC6455。

为什么不用 playwright/selenium：本机没有这两个包，也没有 pip 权限；
更重要的是 CDP 能拿到 `Fetch.requestPaused` 这种**网络层**钩子，
范围校验必须挂在那里——上层框架的 route 拦截也能做，但多一层黑盒。

两个容易踩的点（都在这台机器上真踩过）：
1. Chromium 的握手响应**每条 header 后面都多一个空行**，所以不能见到第一个
   \\r\\n\\r\\n 就收工，否则剩下的 header 会被当成第一帧数据。
2. `Fetch.requestPaused` 事件必须有人应答，否则页面永久卡死；而应答本身又是一次
   RPC，会读到更多事件。所以 send 和 pump 必须分开：不能"发一条就阻塞等它"。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x2, 0x8, 0x9, 0xA


class CdpError(Exception):
    pass


class WebSocket:
    """够用的 websocket 客户端：发文本帧、收文本帧、处理 ping/close。"""

    def __init__(self, host: str, port: int, path: str, timeout: float = 20.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key)
        )
        self.sock.sendall(req.encode("ascii"))
        head, rest = self._read_http_block()
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise CdpError("websocket 握手失败：%s" % head.split(b"\r\n")[0][:120])
        expect = base64.b64encode(
            hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")
        if expect.lower().encode() not in head.lower():
            raise CdpError("Sec-WebSocket-Accept 不匹配")
        self._buf = rest

    # ---- 底层 ----
    def _read_http_block(self) -> Tuple[bytes, bytes]:
        """等整个响应头块收尾（以空行结束），并把后续字节留作帧缓冲。"""
        buf = b""
        while True:
            if buf.startswith(b"HTTP/1.") and buf.endswith(b"\r\n\r\n"):
                idx = buf.rfind(b"\r\n\r\n")
                return buf[:idx], buf[idx + 4:]
            chunk = self.sock.recv(4096)
            if not chunk:
                raise CdpError("连接在握手阶段被关闭：%r" % buf[:200])
            buf += chunk

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self._buf)))
            if not chunk:
                raise CdpError("连接已关闭")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def send_text(self, text: str) -> None:
        raw = text.encode("utf-8")
        header = bytearray([0x80 | OP_TEXT])
        n = len(raw)
        if n < 126:
            header.append(0x80 | n)
        elif n < (1 << 16):
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(raw))
        self.sock.sendall(bytes(header) + masked)

    def recv_frame(self) -> Tuple[int, bytes]:
        _fin, opcode, payload = self._read_frame()
        return opcode, payload

    def _read_frame(self) -> Tuple[bool, int, bytes]:
        b0, b1 = self._recv_exact(2)
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._recv_exact(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else b""
        payload = self._recv_exact(n) if n else b""
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload

    def _send_control(self, opcode: int, payload: bytes = b"") -> None:
        mask = os.urandom(4)
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + body)

    def recv_text(self) -> str:
        chunks: List[bytes] = []
        while True:
            fin, op, payload = self._read_frame()
            if op == OP_CLOSE:
                raise CdpError("对端关闭连接")
            if op == OP_PING:
                self._send_control(OP_PONG, payload)
                continue
            if op == OP_PONG:
                continue
            chunks.append(payload)
            if fin:
                return b"".join(chunks).decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.sendall(bytes([0x80 | OP_CLOSE, 0x80]) + os.urandom(4))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class CdpSession:
    """JSON-RPC 会话：send 不阻塞，pump 处理事件并分发响应。

    事件处理器可以是可重入的：处理 `Fetch.requestPaused` 时会再调 send（继续/拦截），
    然后回到 pump 继续跑，不会死等自己。
    """

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self._id = 0
        self.events: List[Dict[str, Any]] = []
        self._responses: Dict[int, Dict[str, Any]] = {}
        self.handler: Optional[Callable[[Dict[str, Any]], None]] = None

    def send(self, method: str, params: Optional[Dict[str, Any]] = None,
             session: Optional[str] = None) -> int:
        self._id += 1
        mid = self._id
        msg: Dict[str, Any] = {"id": mid, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.ws.send_text(json.dumps(msg))
        return mid

    def pump(self, deadline: float) -> Dict[str, Any]:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise CdpError("CDP 等待超时")
        self.ws.sock.settimeout(max(0.05, remaining))
        try:
            raw = self.ws.recv_text()
        except socket.timeout:
            raise CdpError("CDP 等待超时")
        msg = json.loads(raw)
        if "id" in msg:
            self._responses[msg["id"]] = msg
        else:
            self.events.append(msg)
            if self.handler is not None:
                self.handler(msg)
        return msg

    def wait(self, mid: int, timeout: float = 20.0) -> Dict[str, Any]:
        deadline = time.time() + timeout
        while mid not in self._responses:
            self.pump(deadline)
        msg = self._responses.pop(mid)
        if "error" in msg:
            raise CdpError(msg["error"].get("message", "CDP 调用失败") + " (%s)" % msg["error"].get("code"))
        return msg.get("result", {})

    def call(self, method: str, params: Optional[Dict[str, Any]] = None,
             timeout: float = 20.0, session: Optional[str] = None) -> Dict[str, Any]:
        return self.wait(self.send(method, params, session), timeout)

    def wait_event(self, method: str, timeout: float = 20.0,
                   predicate: Optional[Callable[[Dict[str, Any]], bool]] = None) -> Dict[str, Any]:
        deadline = time.time() + timeout
        def _find() -> Optional[Dict[str, Any]]:
            for i, ev in enumerate(self.events):
                if ev.get("method") == method and (predicate is None or predicate(ev)):
                    return self.events.pop(i)
            return None
        while True:
            hit = _find()
            if hit is not None:
                return hit
            if time.time() > deadline:
                raise CdpError("等待事件 %s 超时" % method)
            self.pump(deadline)

    def drain(self, method: Optional[str] = None) -> List[Dict[str, Any]]:
        if method is None:
            out, self.events = self.events, []
            return out
        hit = [e for e in self.events if e.get("method") == method]
        self.events = [e for e in self.events if e.get("method") != method]
        return hit

    def close(self) -> None:
        self.ws.close()


def ws_url_parts(url: str) -> Tuple[str, int, str]:
    parts = urlsplit(url)
    if parts.scheme != "ws":
        raise CdpError("只支持 ws:// 调试端点，收到 %s" % url)
    return parts.hostname or "127.0.0.1", parts.port or 80, parts.path or "/"
