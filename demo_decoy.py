# -*- coding: utf-8 -*-
"""decoy 负对照演示：同一份相似度证据，在两种服务端语义下判出两个结论。

一段真 HTTP 服务（三个接口）：
  /api/orders?id=N  按 id 查，只有 7 存在   → decoy 拿到 404 → 越权成立
  /api/any?id=N     不看 id，任何值同一份   → decoy 拿到同一份 → 越权不成立
  /admin            403，用来演示"被范围判定挡住"与"连不上"的区别

三段输出 + 一段"连不上"：
  ① 有归属校验 → confirmed，负对照 404
  ② 不看 id    → refuted 0.35，负对照 200 且内容相同
  ③ 端口没开   → hypothesis 0.50，stop_reason=unreachable

要点：判"两个身份读到同一份内容"之前，先证明这份内容真的和对象 id 有关。
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

BODY = json.dumps({"id": 7, "user_id": 3, "total": 99}).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "decoy/1.0"

    def _json(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        oid = (parse_qs(parts.query).get("id") or [""])[0]
        if parts.path == "/api/orders":
            if oid == "7":
                self._json(BODY)
            else:
                self._json(b'{"error": "not found"}', 404)
        elif parts.path == "/api/any":
            self._json(BODY)
        else:
            self._json(b'{"error": "no route"}', 404)

    def log_message(self, *a):
        pass


def run(port, url, title):
    """跑一发 idor-object-ref，打印每一次出网请求与最终判定。"""
    root = tempfile.mkdtemp(prefix="pta-decoy-")
    try:
        init_workspace(root, Scope(engagement_id="ENG-DCY", domains=("127.0.0.1",),
                                   allow_private=True, allowed_ports=(port,),
                                   rate_per_host=200, max_requests=200))
        ws = open_workspace(root, dns=DnsPin(resolver=lambda h: ["127.0.0.1"]))
        ws.vault.put("cred/alice/authorization", "Bearer A")
        ws.vault.put("cred/bob/authorization", "Bearer B")
        orig = ws.probe.run
        sent = []

        def traced(req):
            r = orig(req)
            sent.append(req.url.rsplit("=", 1)[-1] if "=" in req.url else req.url)
            print("      %-4s %-44s id=%-9s -> %s"
                  % (req.method, req.url.rsplit("/api/", 1)[-1],
                     req.identity, (r.extract.status if r.extract else r.status)))
            return r

        ws.probe.run = traced
        ex = Executor(ws.probe, ws.store, "ENG-DCY")
        tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == "idor-object-ref"][0])
        f = ex.run(tpl, Target(url=url, param_path="query:id",
                               identity_baseline="alice", identity_probe="bob"))
        m = f.verdict.get("metrics") or {}
        print("    %-30s %-11s 置信度 %.3f  similarity=%s decoy=%s"
              % (title, f.status, f.confidence, m.get("similarity"),
                 m.get("decoy_status")))
        print("      理由：%s" % f.verdict.get("rationale"))
        return f, sent
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("真 HTTP 服务：127.0.0.1:%d\n" % port)

    # 一个确定没人监听的端口，用来演示"连不上"
    probe_sock = socket.socket()
    probe_sock.bind(("127.0.0.1", 0))
    dead_port = probe_sock.getsockname()[1]
    probe_sock.close()

    ok = True
    try:
        print("① 服务端按 id 查（只有 7 存在）")
        a, sa = run(port, "http://127.0.0.1:%d/api/orders?id=7" % port, "越权成立？")
        ok = ok and a.status == "confirmed" and a.verdict["metrics"].get("decoy_status") == 404
        ok = ok and sa == ["7", "999999999", "7"]
        print()

        print("② 服务端不看 id（任何值同一份）")
        b, sb = run(port, "http://127.0.0.1:%d/api/any?id=7" % port, "越权成立？")
        ok = ok and b.status == "refuted" and abs(b.confidence - 0.35) < 1e-9
        ok = ok and b.verdict["metrics"].get("decoy_similarity") == 1.0
        print()

        print("③ 端口没开（工具不该把它写成「没洞」）")
        c, _ = run(dead_port, "http://127.0.0.1:%d/api/orders?id=7" % dead_port, "越权成立？")
        ok = ok and c.status == "hypothesis" and abs(c.confidence - 0.50) < 1e-9
        ok = ok and c.stop_reason == "unreachable"
        print()

        print("结果：%s" % ("OK（负对照拦下「不看 id」的接口；连不上不判否）" if ok else "FAIL"))
        return 0 if ok else 1
    finally:
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
