# -*- coding: utf-8 -*-
"""证据 → PoC 演示：结论里那一发请求，能不能原样拿出来重打一次。

一段真 HTTP 服务 + 一次真判定，然后做四件事：
  ① 跑 idor-object-ref：alice 和 bob 读到同一份订单 → confirmed；
  ② `pta show --last`：把结论还原成「这一发是什么、证明了什么」+ 一条 curl；
  ③ 另外两种渲染（raw 报文、python 片段）；
  ④ 用这份 PoC 真打回去，比对响应体与当时录到的那份完全一致。

要点：报告里的 confidence 只是结论；能拿去复现的是**请求本身**。
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import poc as poc_mod, vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

ORDER = json.dumps({"id": 7, "user_id": 3, "total": 99, "owner": "alice"}).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    """只有 id=7 存在；哪个身份来读都返回同一份（这就是越权）。"""

    server_version = "poc/1.0"

    def _json(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        oid = (parse_qs(parts.query).get("id") or [""])[0]
        if parts.path == "/api/orders" and oid == "7":
            self._json(ORDER)
        else:
            self._json(b'{"error": "not found"}', 404)

    def log_message(self, *a):
        pass


def judge(root, port, ws):
    tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == "idor-object-ref"][0])
    f = Executor(ws.probe, ws.store, "ENG-POC").run(
        tpl, Target(url="http://127.0.0.1:%d/api/orders?id=7" % port, param_path="query:id",
                    identity_baseline="alice", identity_probe="bob"))
    print("    判定：%s  置信度 %.3f  requests_used=%d" % (f.status, f.confidence, f.requests_used))
    roles = f.verdict.get("roles") or {}
    print("    角色表：%s" % "，".join("%s=%s" % (r, e[:8]) for e, r in roles.items()))
    return f


def show_cli(root):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(HERE, "src")
    env["PYTHONIOENCODING"] = "utf-8"
    out = subprocess.run([sys.executable, "-m", "pta.cli", "show", "--root", root, "--last"],
                         capture_output=True, text=True, encoding="utf-8", env=env)
    for line in (out.stdout or "").splitlines():
        print("    " + line)
    if out.returncode != 0:
        print("    (show 失败：%s)" % (out.stderr or "")[-300:])


def replay(p, ws):
    """把 PoC 真发一次，返回 (status, body_bytes)。"""
    sp = urlsplit(p.url)
    conn = http.client.HTTPConnection(sp.hostname, sp.port or 80, timeout=10)
    headers = {k: v for k, v in p.headers if k.lower() != "host"}
    conn.request(p.method, p.target, body=p.body or None, headers=headers)
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r.status, body


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("真 HTTP 服务：127.0.0.1:%d（只有 id=7 存在）\n" % port)

    root = tempfile.mkdtemp(prefix="pta-poc-")
    ok = True
    try:
        init_workspace(root, Scope(engagement_id="ENG-POC", domains=("127.0.0.1",),
                                   allow_private=True, allowed_ports=(port,),
                                   rate_per_host=200, max_requests=200))
        ws = open_workspace(root, dns=DnsPin(resolver=lambda h: ["127.0.0.1"]))
        ws.vault.put("cred/alice/authorization", "Bearer alice-token")
        ws.vault.put("cred/bob/authorization", "Bearer bob-token")
        ws.vault.put("cred/bob/cookie", "session=f3a91c")

        print("① 跑一次判定")
        f = judge(root, port, ws)
        ok = ok and f.status == "confirmed"
        print()

        print("② pta show --last（结论 → 这一发 + 它证明了什么）")
        show_cli(root)
        print()

        p = poc_mod.load(ws, f.id)
        ok = ok and p.role == "probe" and "id=7" in p.url
        ok = ok and ["Bearer bob-token"] == [v for k, v in p.headers
                                             if k.lower() == "authorization"]
        print("③ 另外两种渲染")
        print("  --- raw（可以直接喂 nc / Burp / 任何 raw 客户端）---")
        for line in poc_mod.render(p, "raw").splitlines()[:6]:
            print("    " + line)
        print("    ...")
        print("  --- python（标准库，不装 requests 也能跑）---")
        for line in poc_mod.render(p, "python").splitlines():
            print("    " + line)
        print()

        print("④ 把这份 PoC 真打回去")
        status, body = replay(p, ws)
        row = ws.store.get_evidence_row(p.evidence_id)
        want = ws.cas.get(row["body_sha256"])
        same = hashlib.sha256(body).hexdigest() == hashlib.sha256(want).hexdigest()
        print("    重放：%s %s → %d  %d 字节" % (p.method, p.target, status, len(body)))
        print("    与当时录到的证据一致：%s（sha256 %s…）"
              % ("是" if same else "否", hashlib.sha256(body).hexdigest()[:16]))
        ok = ok and status == 200 and same
        print()

        print("结果：%s" % ("OK（结论能还原成请求，请求能复现同一份响应）" if ok else "FAIL"))
        return 0 if ok else 1
    finally:
        shutil.rmtree(root, ignore_errors=True)
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
