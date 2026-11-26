# -*- coding: utf-8 -*-
"""身份凭证：把浏览器里的登录态搬进工作区。

三段：
  ① 解析：devtools 的 `Copy as cURL` → 只留身份头（Cookie / Authorization / X-CSRF-Token）
  ② 落库：写进凭证仓，`pta auth ls` 只看得到掩码
  ③ 生效：probe 每次带这个身份发请求，都会自动附上这些头

跑法：python demo_auth.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import credentials, vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.probe import ProbeRequest  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

# 从 devtools 复制出来的样子：多行、反斜杠续行、混着浏览器指纹头
CURL = r"""curl 'http://127.0.0.1:PORT/api/me' \
  -H 'accept: application/json, text/plain, */*' \
  -H 'accept-language: zh-CN,zh;q=0.9' \
  -H 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.aaaaaaaaaaaaaaaaaaaa' \
  -H 'cookie: session=s%3A7f3c9d2e; csrftoken=8c1f2b' \
  -H 'sec-ch-ua: "Chromium";v="157"' \
  -H 'sec-fetch-mode: cors' \
  -H 'x-csrf-token: 8c1f2b' \
  -H 'referer: http://127.0.0.1:PORT/app' \
  -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/157.0.0.0' \
  --compressed"""


class Site(BaseHTTPRequestHandler):
    """只认 alice 那套头；少了任何一条都 401。"""

    server_version = "authlab/1.0"
    seen = []

    def _json(self, status, body):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        h = {k.lower(): v for k, v in self.headers.items()}
        type(self).seen.append((self.path, h))
        ok = (h.get("authorization", "").startswith("Bearer ")
              and "session=" in h.get("cookie", "")
              and h.get("x-csrf-token") == "8c1f2b")
        if self.path == "/api/me":
            if ok:
                self._json(200, {"user": "alice", "role": "admin", "tenant": "acme"})
            else:
                self._json(401, {"error": "unauthorized"})
        elif self.path == "/login":
            body = b'<html><form><input type="password" name="pw"></form></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, *a):
        pass


def show(title):
    print("\n" + "=" * 78)
    print(title)
    print("-" * 78)


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    port = srv.server_address[1]
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % port
    curl = CURL.replace("PORT", str(port))
    checks = []

    root = tempfile.mkdtemp(prefix="pta-auth-")
    try:
        show("① 解析 Copy as cURL（只留身份头，指纹头丢掉）")
        imported = credentials.parse_curl(curl)
        print("  方法=%s  URL=%s" % (imported.method, imported.url))
        for name, value in imported.headers:
            print("    保留 %-16s %s" % (name, credentials.mask(value)))
        print("  丢弃：%s" % ", ".join(sorted(set(imported.dropped))))
        checks.append(("只留下身份头", {n.lower() for n, _ in imported.headers}
                       == {"authorization", "cookie", "x-csrf-token", "referer"}
                       and "user-agent" in {d.lower() for d in imported.dropped}))

        show("② 落库（值只显示掩码）+ ③ 用这个身份发请求")
        init_workspace(root, Scope(engagement_id="ENG-AUTH",
                                   domains=("127.0.0.1",), allow_private=True,
                                   allowed_ports=(port,), rate_per_host=200,
                                   max_requests=50))
        ws = open_workspace(root, dns=DnsPin(resolver=lambda h: ["127.0.0.1"]))
        for name, value in imported.headers:
            ws.vault.put("cred/alice/%s" % name.lower(), value)
        print("  身份清单：")
        for ident in ws.vault.identities():
            names = [r.rsplit("/", 1)[-1] for r in ws.vault.items("cred/%s/" % ident)]
            print("    %-6s 头 %d 条：%s" % (ident, len(names), ", ".join(names)))

        # 同一个 URL：没有身份 → 401；带 alice → 200
        bare = ws.probe.run(ProbeRequest(
            action_id="demo:bare", url=base + "/api/me", identity="none", label="demo", level="L1"))
        print("  无身份：HTTP %s" % (bare.extract.status if bare.extract else bare.status))
        checks.append(("无身份被拒", bare.extract is not None and bare.extract.status == 401))

        logged = ws.probe.run(ProbeRequest(
            action_id="demo:logged", url=base + "/api/me", identity="alice", label="demo", level="L1"))
        print("  带 alice：HTTP %s" % (logged.extract.status if logged.extract else logged.status))
        checks.append(("带身份通了", logged.extract is not None and logged.extract.status == 200))

        # 服务端视角：这三条头就是从 curl 里搬过来的
        got = [h for p, h in Site.seen if p == "/api/me" and h.get("x-csrf-token")][-1]
        print("  服务端实际收到：authorization=%s  cookie=%s  x-csrf-token=%s"
              % (got.get("authorization", "")[:14] + "…",
                 got.get("cookie", "")[:18] + "…",
                 got.get("x-csrf-token")))
        checks.append(("身份头真的发出去了",
                       got.get("x-csrf-token") == "8c1f2b"
                       and got.get("authorization", "").startswith("Bearer ")))

        # 模板执行时也一样，不用每次手工传头
        ex = Executor(ws.probe, ws.store, "ENG-AUTH")
        f = ex.run(vhx.load([t for t in vhx.TEMPLATES
                             if t["id"] == "info-disclosure-artifact"][0]),
                   Target(url=base + "/api/me", identity_baseline="alice"))
        print("  模板执行（info-disclosure-artifact）：status=%s 证据 %d 条"
              % (f.status, len(f.evidence_ids)))

        show("④ 检查身份还登不登着")
        res = ws.probe.run(ProbeRequest(
            action_id="demo:check", url=base + "/api/me", identity="alice",
            label="auth", level="L1"))
        print("  /api/me → HTTP %s（%s）" % (
            res.extract.status if res.extract else "?",
            "还登着" if res.extract and res.extract.status == 200 else "掉登录了"))
        res2 = ws.probe.run(ProbeRequest(
            action_id="demo:check2", url=base + "/login", identity="alice",
            label="auth", level="L1"))
        print("  /login  → HTTP %s" % (res2.extract.status if res2.extract else "?"))
        checks.append(("check 能区分登录页", res.extract is not None
                       and res.extract.status == 200 and res2.extract.status == 200))

        show("⑤ cookies.txt 也能吃（Netscape 7 列 / k=v 两种）")
        jar = credentials.parse_cookie_file(
            "# Netscape HTTP Cookie File\n"
            "127.0.0.1\tFALSE\t/\tFALSE\t0\tsession\ts%3A7f3c9d2e\n"
            "127.0.0.1\tFALSE\t/\tFALSE\t0\tcsrftoken\t8c1f2b\n")
        print("  %s" % jar)
        checks.append(("cookie 文件合并", jar == "session=s%3A7f3c9d2e; csrftoken=8c1f2b"))
    finally:
        shutil.rmtree(root, ignore_errors=True)
        srv.shutdown()

    print("\n" + "=" * 78)
    print("自检：")
    for name, passed in checks:
        print("  %s %s" % ("OK  " if passed else "FAIL", name))
    bad = [n for n, p in checks if not p]
    print("\n结果：%s" % ("OK（登录态只搬一次，之后每次请求自动带上）"
                          if not bad else "FAIL（%s）" % ", ".join(bad)))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())

