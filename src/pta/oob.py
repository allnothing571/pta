"""OOB（带外）收集器：HTTP + DNS 回连。

为什么需要它：SSRF、盲注、盲 XXE 这类漏洞在响应里什么都不体现，唯一的外部证据
是目标"回头来找我们"。所以 OOB 通道必须由 harness 自己控制——token 不可猜、
回连来源可区分自触发、每次回连都进证据库。

三条设计约束：
1. token 由 harness 生成（secrets），模型只能请求"arm 一个 token"，不能指定内容；
2. 回连记录与普通证据同等对待：body 进 CAS，一行 evidence，role=callback；
3. `our_egress_ips` 命中即标 self_trigger，oracle 据此拒绝判定（防止自己打自己）。
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

MAX_BODY = 4096


@dataclass
class Callback:
    token: str
    protocol: str            # http | dns
    method: str
    path: str
    query: str
    source_ip: str
    user_agent: str
    referer: str
    body: bytes
    ts: str
    count: int = 1
    self_trigger: bool = False

    @property
    def fingerprint(self) -> str:
        raw = "|".join((self.token, self.protocol, self.method, self.path, self.source_ip))
        import hashlib
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_json(self) -> Dict[str, object]:
        import hashlib
        return {
            "token": self.token, "protocol": self.protocol, "method": self.method,
            "path": self.path, "query": self.query, "source_ip": self.source_ip,
            "user_agent": self.user_agent[:160], "referer": self.referer[:160],
            "body_len": len(self.body),
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "ts": self.ts, "count": self.count, "self_trigger": self.self_trigger,
        }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class _QuietHttpServer(ThreadingHTTPServer):
    """扫描器/客户端半途断连是常态，不要往 stderr 刷栈。"""

    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class OobCollector:
    def __init__(self, public_host: str = "oob.test", http_port: int = 0, dns_port: int = 0,
                 bind_host: str = "0.0.0.0", our_egress_ips: Tuple[str, ...] = (),
                 max_body: int = MAX_BODY):
        self.public_host = public_host
        self.bind_host = bind_host
        self.our_egress_ips = set(our_egress_ips)
        self.max_body = max_body
        self.http_port = http_port
        self.dns_port = dns_port
        self._lock = threading.Lock()
        self._tokens: Dict[str, dict] = {}
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._dns_sock: Optional[socket.socket] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ---------- 生命周期 ----------
    def start(self) -> "OobCollector":
        self._start_http()
        self._start_dns()
        return self

    def _start_http(self) -> None:
        collector = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # 静默
                pass

            def _handle(self) -> None:
                body = b""
                length = int(self.headers.get("Content-Length") or 0)
                if length > 0:
                    body = self.rfile.read(min(length, collector.max_body))
                collector._record_http(self, body)
                payload = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_HEAD = _handle

        self._httpd = _QuietHttpServer((self.bind_host, self.http_port), Handler)
        self.http_port = self._httpd.server_port
        self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._http_thread.start()

    def _start_dns(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_host, self.dns_port))
        sock.settimeout(0.5)
        self._dns_sock = sock
        self.dns_port = sock.getsockname()[1]
        self._dns_thread = threading.Thread(target=self._dns_loop, daemon=True)
        self._dns_thread.start()

    def _dns_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._dns_sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                name, end = _parse_qname(data, 12)
            except Exception:
                continue
            self._record("dns", token=(name.split(".")[0] if name else ""), method="QUERY",
                         path=name, query=str(_qtype(data, end)), source_ip=addr[0],
                         user_agent="", referer="", body=b"")
            resp = _dns_noerror(data, end)
            try:
                self._dns_sock.sendto(resp, addr)
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._dns_sock is not None:
            try:
                self._dns_sock.close()
            finally:
                self._dns_sock = None

    # ---------- token ----------
    def arm(self, label: str, note: str = "", token: Optional[str] = None) -> str:
        """登记一个回连 token。token 只能由这里给，模型无权指定具体值。"""
        token = token or secrets.token_hex(8)
        with self._lock:
            self._tokens[token] = {"label": label, "note": note, "created_at": _now(),
                                   "callbacks": []}
        return token

    def tokens(self) -> List[Dict[str, object]]:
        with self._lock:
            return [{"token": t, "label": v["label"], "note": v["note"],
                     "created_at": v["created_at"], "callbacks": len(v["callbacks"])}
                    for t, v in self._tokens.items()]

    def url_for(self, token: str) -> str:
        host = self.public_host
        if self.http_port in (80, 0):
            return "http://%s/t/%s" % (host, token)
        return "http://%s:%d/t/%s" % (host, self.http_port, token)

    def host_for(self, token: str) -> str:
        return "%s.%s" % (token, self.public_host)

    # ---------- 记录与查询 ----------
    def _record_http(self, handler, body: bytes) -> None:
        path = handler.path.split("?", 1)[0]
        query = handler.path.split("?", 1)[1] if "?" in handler.path else ""
        token = ""
        if "/t/" in path:
            token = path.split("/t/", 1)[1].split("/", 1)[0]
        elif path.startswith("/o/"):
            token = path.split("/o/", 1)[1].split("/", 1)[0]
        if not token:
            host = (handler.headers.get("Host") or "").split(":", 1)[0]
            if "." in host:
                token = host.split(".", 1)[0]
        self._record("http", token=token, method=handler.command, path=path, query=query[:512],
                     source_ip=handler.client_address[0],
                     user_agent=handler.headers.get("User-Agent") or "",
                     referer=handler.headers.get("Referer") or "", body=body[:self.max_body])

    def _record(self, protocol: str, token: str, method: str, path: str, query: str,
                source_ip: str, user_agent: str, referer: str, body: bytes) -> None:
        cb = Callback(token=token, protocol=protocol, method=method, path=path, query=query,
                      source_ip=source_ip, user_agent=user_agent, referer=referer,
                      body=body, ts=_now(),
                      self_trigger=source_ip in self.our_egress_ips)
        with self._lock:
            rec = self._tokens.get(token)
            if rec is None:
                return  # 未知 token 不记录：不能让人拿我们的收集器当免费打点器
            for existing in rec["callbacks"]:
                if existing.fingerprint == cb.fingerprint:
                    existing.count += 1
                    return
            rec["callbacks"].append(cb)

    def check(self, token: str) -> List[Callback]:
        with self._lock:
            rec = self._tokens.get(token)
            return list(rec["callbacks"]) if rec else []

    def wait(self, token: str, timeout: float = 5.0, poll: float = 0.1) -> List[Callback]:
        deadline = time.time() + timeout
        while True:
            calls = self.check(token)
            if calls or time.time() >= deadline:
                return calls
            time.sleep(poll)

    # ---------- 测试用：不起网络也能造回连 ----------
    def inject(self, token: str, protocol: str = "http", source_ip: str = "203.0.113.9",
               path: str = "/t/%s", body: bytes = b"") -> Optional[Callback]:
        self._record(protocol, token=token, method="GET",
                     path=path % token if "%s" in path else path, query="",
                     source_ip=source_ip, user_agent="inject", referer="", body=body)
        calls = self.check(token)
        return calls[-1] if calls else None


# ---------- 最小 DNS 报文处理 ----------
def _parse_qname(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated qname")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("ascii", "ignore"))
        offset += length
    return ".".join(labels), offset


def _qtype(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return 0
    return struct.unpack(">H", data[offset:offset + 2])[0]


def _dns_noerror(query: bytes, qend: int) -> bytes:
    """回一个标准 NOERROR、无回答的响应，让解析器立刻结束等待。"""
    if len(query) < 12:
        return query
    tid = query[:2]
    question = query[12:qend + 4]
    header = tid + b"\x81\x80" + struct.pack(">HHHH", 1, 0, 0, 0)
    return header + question


def write_tokens(path: str, collector: OobCollector) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(collector.tokens(), fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
