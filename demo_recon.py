"""侦察层演示：给一个首页，看它自己铺出多少东西。

跑法：python demo_recon.py
起一个本地 HTTP 服务（带链接、表单、JS、一个 403 的 admin、一个站外链接），
建工作区 → crawl → 打印页面/接口/参数 → plan → 打印候选。
重点看三件事：
1. 站外链接和 /admin（deny_paths 里没写，但 403 仍被记为拒绝模板候选）不会拖垮爬取；
2. 抓过的页面自带 query 参数，Planner 立刻能提出 idor / sqli 候选；
3. 每一页都落了证据，report.json 只是给人看的副本。
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta.planner import Planner  # noqa: E402
from pta.recon import Recon, write_report  # noqa: E402
from pta.scope import Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

INDEX = b"""<!doctype html><html><head>
<script src="/static/app.js"></script></head><body>
<a href="/search?q=widget">search</a>
<a href="/api/users?id=1">user 1</a>
<a href="/api/users?id=2">user 2</a>
<a href="/admin">admin</a>
<a href="https://example.invalid/elsewhere">elsewhere</a>
<form action="/api/search" method="get"><input name="q"></form>
</body></html>"""

APP_JS = b"""fetch("/api/v2/orders?limit=10");"""


class Site(BaseHTTPRequestHandler):
    def log_message(self, *a):        # 安静
        pass

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX)
        elif path == "/static/app.js":
            self._send(200, "application/javascript", APP_JS)
        elif path == "/search":
            self._send(200, "application/json", b'{"total":1,"items":[{"id":1}]}')
        elif path == "/api/search":
            self._send(200, "application/json", b'{"total":0,"items":[]}')
        elif path == "/api/users":
            self._send(200, "application/json", b'{"id":1,"email":"a@corp.test","role":"user"}')
        elif path == "/admin":
            self._send(403, "text/html; charset=utf-8", b"<h1>forbidden</h1>")
        else:
            self._send(404, "text/plain", b"not found")


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    seed = "http://127.0.0.1:%d/" % port

    root = os.path.join(tempfile.mkdtemp(prefix="pta-recon-"), "eng")
    init_workspace(root, Scope(engagement_id="ENG-RECON", domains=("127.0.0.1",),
                               allow_private=True, allowed_ports=(port,)))
    ws = open_workspace(root)
    try:
        print("种子：%s" % seed)
        report = Recon(ws, max_pages=10, max_depth=2).run([seed])
        path = write_report(ws, report)

        print("\n抓到 %d 页 / %d 次请求" % (len(report.pages), report.requests))
        for p in report.pages:
            print("  %-3d %-50s %s" % (p.status, p.url.replace(seed, "/"), p.content_type))
        print("\nJS 里的接口：%s" % (", ".join(report.endpoints()) or "（无）"))
        print("参数发现：%s" % (", ".join(report.params()) or "（无）"))
        skipped = {}
        for s in report.skipped:
            key = s["reason"].split(":")[0]
            skipped[key] = skipped.get(key, 0) + 1
        print("跳过：%s" % json.dumps(skipped, ensure_ascii=False))
        print("报告：%s" % path)

        plan = Planner(ws).plan()
        print("\nPlanner 候选（%d）：" % len(plan.candidates))
        for c in plan.candidates:
            print("  %.2f  %-26s %s  %s" % (c.priority, c.template_id,
                                            c.method, c.url))
        ok = len(report.pages) >= 3 and plan.candidates and skipped.get("cross_origin")
        print("\n结果：%s" % ("OK（自己发现端点，候选非空，站外链接没跟出去）" if ok
                              else "FAIL"))
        return 0 if ok else 1
    finally:
        srv.shutdown()
        shutil.rmtree(os.path.dirname(root), ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
