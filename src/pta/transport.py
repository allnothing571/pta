"""传输层：唯一允许打开 socket 的地方。

三种实现：
- MockTransport     测试/离线演示，按路由表返回固定响应
- DirectPinnedTransport  直连，但只连 DnsPin 给出的 IP（TLS SNI 仍用真实主机名）
- ProxyTransport    强制走代理 CONNECT，本地不做任何直连

P0 验收⑤要求"关掉出口代理后所有 http_probe 失败"：Scope.egress_proxy 一旦设置，
ProbeTool 就拒绝构造 DirectPinnedTransport。
"""
from __future__ import annotations

import http.client
import io
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

from .models import RawResponse, ResolvedRequest

MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# Windows 上 _now() 的粒度是 ~15.6ms（GetTickCount64），
# 本地/内网响应用它量出来常常是 0.0，时间盲注的样本会被整批丢掉。
# 统一用 perf_counter（高精度单调时钟）；三个时间戳必须来自同一个时钟。
_now = time.perf_counter


class TransportError(Exception):
    pass


def _render_request(req: ResolvedRequest) -> bytes:
    # query 必须在线路层做百分号编码：载荷里带空格/单引号/尖括号，
    # 原样拼进请求行会被服务端当非法请求直接 400（P0 的 mock 看不出来）。
    q = "&".join("%s=%s" % (quote(k, safe=""), quote(v, safe="")) for k, v in req.query)
    path = req.raw_path + (("?" + q) if q else "")
    lines = ["%s %s HTTP/1.1" % (req.method.upper(), path)]
    have_host = False
    for k, v in req.headers:
        lines.append("%s: %s" % (k, v))
        if k.lower() == "host":
            have_host = True
    if not have_host:
        lines.append("Host: %s" % req.host)
    if req.body:
        lines.append("Content-Length: %d" % len(req.body))
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + req.body
    return raw


class _ReplayRaw(io.RawIOBase):
    """把已经读出来的字节先吐回去，再接上真 socket。

    `HTTPResponse` 只需要一个能做 `readinto` 的原始流；TLS 层没法窥视，所以
    首字节的代价是"读出来再回放"，不是"读之前看一眼"。
    """

    def __init__(self, sock, head: bytes) -> None:
        self._sock = sock
        self._head = head

    def readable(self) -> bool:
        return True

    def readinto(self, buf) -> int:
        if self._head:
            n = min(len(self._head), len(buf))
            buf[:n] = self._head[:n]
            self._head = self._head[n:]
            return n
        return self._sock.recv_into(buf)


class _ReplaySocket:
    """`http.client.HTTPResponse` 只用到 `makefile()`，这里就只实现它。"""

    def __init__(self, sock, head: bytes) -> None:
        self._sock = sock
        self._head = head

    def makefile(self, mode: str = "rb", *args, **kwargs):
        return io.BufferedReader(_ReplayRaw(self._sock, self._head))


def _read_response(sock, t_send: float) -> RawResponse:
    # 读阶段的超时/断连必须变成 TransportError：否则 socket.timeout 会穿过 probe 的
    # 错误处理，把"这台内网服务不通"升级成"整个演练崩掉"。SSRF 打不可达地址时
    # 这是常态（Windows 上连 169.254.169.254 会一直挂到超时）。
    try:
        return _read_response_inner(sock, t_send)
    except socket.timeout as exc:
        raise TransportError("读响应超时：%s" % exc)
    except OSError as exc:
        raise TransportError("读响应失败：%s" % exc)


def _read_response_inner(sock, t_send: float) -> RawResponse:
    # 先读 1 字节，既能量出首字节时间，又能在服务端一声不吭就断开时给出准确原因。
    # 不能用 recv(1, MSG_PEEK)：SSLSocket.recv 不接受 flags，HTTPS 会直接 ValueError
    # （"non-zero flags not allowed in calls to recv() on ssl.SSLSocket"），
    # 而 MSG_PEEK 在 TLS 上本来也没有意义——解密后的流没有可供窥视的边界。
    # 所以改成"读过再回放"：读出来的这一字节交给下面的 shim 先吐回去。
    first = sock.recv(1)
    t_first = _now()
    if not first:
        raise TransportError("连接被立即关闭")
    resp = http.client.HTTPResponse(_ReplaySocket(sock, first), method="GET")
    resp.begin()
    body = resp.read(MAX_RESPONSE_BYTES)
    t_end = _now()
    headers = [(k, v) for k, v in resp.getheaders()]
    return RawResponse(
        status=resp.status,
        reason=resp.reason or "",
        http_version="HTTP/1.1" if resp.version == 11 else "HTTP/%d" % resp.version,
        headers=tuple(headers),
        body=body,
        t_send=t_send,
        t_first_byte=t_first,
        t_end=t_end,
    )


class Transport:
    name = "abstract"

    def send(self, req: ResolvedRequest, timeout_s: float = 10.0) -> RawResponse:
        raise NotImplementedError


@dataclass
class MockRoute:
    method: str
    host: str
    path_prefix: str
    status: int = 200
    headers: Tuple[Tuple[str, str], ...] = (("Content-Type", "application/json"),)
    body: bytes = b"{}"
    delay_ms: float = 0.0
    identity: Optional[str] = None


class MockTransport(Transport):
    """离线可复现的"服务器"。action_log 里的请求能在这里被重放。"""

    name = "mock"

    def __init__(self, routes: Sequence[MockRoute]):
        self.routes: List[MockRoute] = list(routes)
        self.sent: List[ResolvedRequest] = []

    def send(self, req: ResolvedRequest, timeout_s: float = 10.0) -> RawResponse:
        self.sent.append(req)
        q = "&".join("%s=%s" % (k, v) for k, v in req.query)
        path = req.raw_path + (("?" + q) if q else "")
        identity = ""
        for k, v in req.headers:
            if k.lower() == "authorization":
                identity = v
        for route in self.routes:
            if route.method.upper() != req.method.upper():
                continue
            if route.host and route.host != req.host:
                continue
            if not path.startswith(route.path_prefix):
                continue
            if route.identity is not None and route.identity != identity:
                continue
            t0 = _now()
            if route.delay_ms:
                time.sleep(route.delay_ms / 1000.0)
            t1 = _now()
            return RawResponse(
                status=route.status,
                reason="OK" if route.status < 400 else "ERR",
                http_version="HTTP/1.1",
                headers=route.headers,
                body=route.body,
                t_send=t0,
                t_first_byte=t1,
                t_end=_now(),
            )
        t0 = _now()
        return RawResponse(
            status=404,
            reason="Not Found",
            http_version="HTTP/1.1",
            headers=(("Content-Type", "text/plain"),),
            body=b"mock: no route",
            t_send=t0,
            t_first_byte=t0,
            t_end=_now(),
        )


def _tls_context(verify: bool = True) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class DirectPinnedTransport(Transport):
    """只连 pinned_ip，但 SNI/证书校验用真实主机名，避免把 pin 变成降级。"""

    name = "direct-pinned"

    def __init__(self, tls_verify: bool = True):
        self.ctx = _tls_context(tls_verify)

    def send(self, req: ResolvedRequest, timeout_s: float = 10.0) -> RawResponse:
        if not req.pinned_ip:
            raise TransportError("缺少 DNS pin，拒绝直连")
        t0 = _now()
        try:
            sock = socket.create_connection((req.pinned_ip, req.port), timeout=timeout_s)
        except OSError as exc:
            raise TransportError("连接 %s:%d 失败：%s" % (req.pinned_ip, req.port, exc))
        try:
            if req.scheme == "https":
                sock = self.ctx.wrap_socket(sock, server_hostname=req.host)
            sock.sendall(_render_request(req))
            return _read_response(sock, t0)
        finally:
            try:
                sock.close()
            except OSError:
                pass


class ProxyTransport(Transport):
    """通过 HTTP CONNECT 隧道出去。本地不允许直连，等价于"物理上只能走代理"。"""

    name = "proxy-connect"

    def __init__(self, proxy_host: str, proxy_port: int, tls_verify: bool = True):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.ctx = _tls_context(tls_verify)

    def send(self, req: ResolvedRequest, timeout_s: float = 10.0) -> RawResponse:
        t0 = _now()
        try:
            sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=timeout_s)
        except OSError as exc:
            raise TransportError("代理不可达：%s" % exc)
        try:
            target = "%s:%d" % (req.host, req.port)
            sock.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode("latin-1"))
            line = b""
            while b"\r\n\r\n" not in line:
                chunk = sock.recv(1)
                if not chunk:
                    raise TransportError("代理在 CONNECT 阶段断开")
                line += chunk
                if len(line) > 8192:
                    raise TransportError("代理响应头过长")
            if b" 200 " not in line.split(b"\r\n")[0]:
                raise TransportError("代理拒绝 CONNECT：%s" % line.split(b"\r\n")[0][:120])
            if req.scheme == "https":
                sock = self.ctx.wrap_socket(sock, server_hostname=req.host)
            sock.sendall(_render_request(req))
            return _read_response(sock, t0)
        finally:
            try:
                sock.close()
            except OSError:
                pass


def parse_proxy(spec: str) -> Tuple[str, int]:
    if "://" in spec:
        spec = spec.split("://", 1)[1]
    host, _, port = spec.partition(":")
    return host, int(port or "8080")
