"""本地靶场应用：一个有真实数据库、真实 HTTP、真实 SSRF 的"故意有洞"的服务。

它和 `demo_*.py` 里的假传输不一样——判定的输入全部来自真的 socket：

- `/api/items`      把 `id` 直接拼进 SQL（真 sqlite，真语法错误页）
- `/api/items_safe` 用参数化查询（同一份数据，没有洞）
- `/api/users/<id>` 任何登录用户都能读别人的对象（IDOR）
- `/api/users_safe/<id>` 只允许读自己
- `/api/fetch?url=` 转发请求到任意地址（SSRF）；`/api/fetch_safe` 有域名白名单
- `POST /api/profile` 把请求体里的字段全写进记录（批量赋值提权）；`_safe` 只接受 name

为了能演示时间盲注，`SLEEP(n)` 由这个服务自己执行（MySQL 的 `SLEEP()` 在 sqlite 里不存在）。
这一点要说清楚：*延时是真的在服务端发生*，但它不是"数据库执行了注入"，而是"这个靶场模拟了
一个会 sleep 的数据库"。靶场的价值在于把判定链放到真实网络与时序上跑，不在于复刻 MySQL。

单独跑：python range_target.py --port 8088
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlunsplit

ITEMS = [(1, "widget", 9.9), (2, "gadget", 19.5), (3, "doohickey", 4.25)]
USERS = {1: {"id": 1, "name": "alice", "role": "user", "email": "alice@range.test"},
         2: {"id": 2, "name": "bob", "role": "user", "email": "bob@range.test"},
         3: {"id": 3, "name": "root", "role": "admin", "email": "root@range.test"}}
TOKENS = {"Bearer TOKEN-A": 1, "Bearer TOKEN-B": 2}
SAFE_FETCH_HOSTS = ("cdn.range.test",)

_SLEEP = re.compile(r"SLEEP\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)", re.I)


def _db():
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE items(id INTEGER, name TEXT, price REAL)")
    con.executemany("INSERT INTO items VALUES (?,?,?)", ITEMS)
    con.commit()
    return con


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RangeApp/1.0"

    # 靶场内部"内网 docker"的真实端口。载荷里写的是真实世界的 2375，但这台机器上
    # 2375 常落在 Windows 保留端口区（bind 直接 EACCES），所以 start() 会把它改写成
    # 真正监听成功的端口——靶场本来就是"模拟内网有个 docker"，端口是靶场的内部细节。
    internal_port = 2375

    # ---- 基础 -------------------------------------------------------------
    def log_message(self, *a):
        pass

    def _send(self, status, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Range-App", "1")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _identity(self):
        return TOKENS.get(self.headers.get("Authorization") or "")

    def _q(self):
        return parse_qs(urlsplit(self.path).query)

    # ---- 路由 -------------------------------------------------------------
    def do_GET(self):
        path = urlsplit(self.path).path
        try:
            if path in ("/", "/index.html"):
                return self._send(200, {"app": "range", "endpoints": [
                    "/api/items?id=1", "/api/items_safe?id=1", "/api/users/1",
                    "/api/users_safe/1", "/api/fetch?url=", "/api/profile"]})
            if path == "/api/items":
                return self._items(vuln=True)
            if path == "/api/items_safe":
                return self._items(vuln=False)
            if path == "/api/users":
                return self._user((self._q().get("id") or ["1"])[0], vuln=True)
            if path == "/api/users_safe":
                return self._user((self._q().get("id") or ["1"])[0], vuln=False)
            if path.startswith("/api/users_safe/"):
                return self._user(path.rsplit("/", 1)[1], vuln=False)
            if path.startswith("/api/users/"):
                return self._user(path.rsplit("/", 1)[1], vuln=True)
            if path == "/api/fetch":
                return self._fetch(vuln=True)
            if path == "/api/fetch_safe":
                return self._fetch(vuln=False)
            return self._send(404, {"error": "not found"})
        except BrokenPipeError:
            raise
        except Exception as exc:                     # 靶场：异常都要看得见
            return self._send(500, {"error": "%s: %s" % (type(exc).__name__, exc)})

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw.decode() or "{}")
            if path == "/api/profile":
                return self._profile(data, vuln=True)
            if path == "/api/profile_safe":
                return self._profile(data, vuln=False)
            return self._send(404, {"error": "not found"})
        except Exception as exc:
            return self._send(500, {"error": "%s: %s" % (type(exc).__name__, exc)})

    # ---- 业务 -------------------------------------------------------------
    def _items(self, vuln: bool):
        raw = (self._q().get("id") or ["1"])[0]
        if vuln:
            delay = 0.0
            m = _SLEEP.search(raw)
            if m:
                delay = min(float(m.group(1)), 5.0)
                raw = _SLEEP.sub("1", raw)
            if delay:
                time.sleep(delay)
            sql = "SELECT id,name,price FROM items WHERE id='%s'" % raw
            try:
                con = _db()
                rows = con.execute(sql).fetchall()
            except sqlite3.Error as exc:             # 真语法错误页
                return self._send(500, {"error": "sqlite3.%s: %s" % (type(exc).__name__, exc)})
            return self._send(200, {"items": [{"id": r[0], "name": r[1], "price": r[2]}
                                              for r in rows]})
        con = _db()
        rows = con.execute("SELECT id,name,price FROM items WHERE id=?", (raw,)).fetchall()
        return self._send(200, {"items": [{"id": r[0], "name": r[1], "price": r[2]}
                                          for r in rows]})

    def _user(self, sid: str, vuln: bool):
        me = self._identity()
        if me is None:
            return self._send(401, {"error": "auth required"})
        try:
            uid = int(sid)
        except ValueError:
            return self._send(400, {"error": "bad id"})
        if not vuln and uid != me:
            return self._send(403, {"error": "forbidden"})
        user = USERS.get(uid)
        if user is None:
            return self._send(404, {"error": "no such user"})
        return self._send(200, user)

    def _fetch(self, vuln: bool):
        target = (self._q().get("url") or [""])[0]
        if not target.startswith(("http://", "https://")):
            return self._send(400, {"error": "bad url"})
        parts = urlsplit(target)
        host = parts.hostname or ""
        if vuln and host == "127.0.0.1" and parts.port != type(self).internal_port:
            target = urlunsplit((parts.scheme,
                                 "127.0.0.1:%d" % type(self).internal_port,
                                 parts.path, parts.query, parts.fragment))
        if not vuln and host not in SAFE_FETCH_HOSTS:
            return self._send(403, {"error": "host not allowed"})
        try:
            with urllib.request.urlopen(target, timeout=2.0) as resp:
                body = resp.read(8192)
        except Exception as exc:
            return self._send(502, {"error": "%s: %s" % (type(exc).__name__, exc)})
        return self._send(200, body, ctype="application/json")

    def _profile(self, data, vuln: bool):
        me = self._identity()
        if me is None:
            return self._send(401, {"error": "auth required"})
        record = dict(USERS[me])
        if vuln:
            record.update(data)                      # 把 role/is_admin 一起吞下去
        elif isinstance(data, dict):
            if "name" in data:
                record["name"] = str(data["name"])
        record["_applied"] = sorted(k for k in (data or {}) if k in record) if vuln else ["name"]
        USERS[me] = dict(record)
        return self._send(200, record)


class Dockerd(BaseHTTPRequestHandler):
    """只在内网口上开着的"别人的服务"：SSRF 打进来时回显 Docker 的 /version。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"ApiVersion": "1.43", "MinAPIVersion": "1.12",
                           "GitCommit": "9d6f1b0", "Os": "linux",
                           "KernelVersion": "5.10.0-range"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start(port: int = 0, internal_port: int = 2375):
    """起两个服务：靶场本身，和一个"只在内网"的 docker API。返回 (httpd, dockerd, port)。

    `internal_port` 只是第一个候选：Windows 上 2375 可能在保留端口区，bind 直接
    EACCES，此时退回让系统挑一个空闲端口，并改写 `Handler.internal_port`，让
    SSRF 转发把载荷里的 2375 重定向到真实端口。
    """
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    docker = None
    for candidate in (internal_port, 0):
        try:
            docker = ThreadingHTTPServer(("127.0.0.1", candidate), Dockerd)
        except OSError:
            docker = None
            continue
        break
    if docker is not None:
        Handler.internal_port = docker.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    if docker is not None:
        threading.Thread(target=docker.serve_forever, daemon=True).start()
    return httpd, docker, httpd.server_address[1]


def main() -> int:
    httpd, docker, port = start(int(sys.argv[sys.argv.index("--port") + 1])
                                if "--port" in sys.argv else 8088)
    print("range app  http://127.0.0.1:%d/" % port)
    print("internal   http://127.0.0.1:%d/version  %s"
          % (Handler.internal_port,
             "up" if docker else "（起不来，SSRF 场景跳过）"))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
