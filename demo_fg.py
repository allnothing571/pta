"""F 项第一批演示：改状态的请求，判的是「少了什么」而不是「能不能发」。

四个场景，同一个站点、同一套模板，只有服务端的校验不同：
  A. 不校验 CSRF 令牌：带令牌 200 → 摘掉令牌 200 → 匿名 401
     → 结论 confirmed 0.90（匿名被拒证明"这个接口确实要身份"，
        那么摘掉令牌还能改成功，缺的就只能是令牌校验）
  B. 校验 CSRF 令牌：摘掉令牌 403 → refuted 0.00「防护在起作用」
  C. 匿名也能改成功：不是 CSRF，是缺失授权 → 0.20（改判，不是漏报）
  D. 存储型 XSS：写进去的 `<img data-pta=…>` 在读回页面里原样出现 → confirmed 0.92
     同一段内容被 HTML 转义 → refuted 0.15
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

ENG = "ENG-FG"
TOKEN = "Bearer TOKEN-A"
CSRF = "s3cr3t"

STATE = {"comments": [], "update_hits": []}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # noqa: A003
        pass

    def _send(self, status, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return {}

    def _authed(self):
        return (self.headers.get("Authorization") or "") == TOKEN

    def do_POST(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path.startswith("/api/update"):
            if not self._authed():
                return self._send(401, '{"error": "unauthorized"}')
            strict = path.endswith("strict")
            token = self.headers.get("x-csrf-token") or ""
            if strict and token != CSRF:
                return self._send(403, '{"error": "csrf token invalid"}')
            STATE["update_hits"].append({"path": path, "token": token})
            return self._send(200, '{"ok": true, "updated": 1}')
        if path.startswith("/api/public"):
            # 匿名也能过：这不是 CSRF，是接口压根没做授权
            return self._send(200, '{"ok": true}')
        if path.startswith("/api/comments"):
            data = self._body()
            STATE["comments"].append(str(data.get("content") or ""))
            return self._send(201, '{"id": %d}' % len(STATE["comments"]))
        return self._send(404, '{"error": "not found"}')

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path.startswith("/api/comments"):
            escape = path.endswith("-safe")
            rows = []
            for text in STATE["comments"]:
                if escape:
                    text = (text.replace("&", "&amp;").replace("<", "&lt;")
                            .replace(">", "&gt;").replace('"', "&quot;"))
                rows.append("<div class=c>%s</div>" % text)
            return self._send(200, "<html><body>%s</body></html>" % "".join(rows),
                              "text/html; charset=utf-8")
        return self._send(404, '{"error": "not found"}')


def serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def ws_for(root, port):
    init_workspace(root, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                               allow_private=True, allowed_ports=(port,),
                               rate_per_host=200, max_requests=200))
    ws = open_workspace(root)
    ws.vault.put("cred/alice/authorization", TOKEN)
    ws.vault.put("cred/alice/x-csrf-token", CSRF)
    return ws


def tpl(tid):
    return vhx.load([t for t in vhx.TEMPLATES if t["id"] == tid][0])


def main():
    srv, port = serve()
    base = "http://127.0.0.1:%d" % port
    checks = []
    try:
        print("=" * 78)
        print("P2.9 改状态的请求：判的是「少了什么」")
        print("=" * 78)
        print("站点：%s（/api/update /api/update-strict /api/public /api/comments）" % base)
        print()

        cases = [
            ("A 不校验令牌", "csrf-token-not-enforced", "/api/update", port, None,
             {"control_url": "/api/update"}, "confirmed"),
            ("B 校验令牌", "csrf-token-not-enforced", "/api/update-strict", port, None,
             {"control_url": "/api/update-strict"}, "refuted"),
            ("C 匿名也能改", "csrf-token-not-enforced", "/api/public", port, None,
             {"control_url": "/api/public"}, "refuted"),
            ("D 回读原样渲染", "xss-stored-marker", "/api/comments", port, "body:content",
             {}, "confirmed"),
            ("E 回读被转义", "xss-stored-marker", "/api/comments-safe", port, "body:content",
             {}, "refuted"),
        ]

        results = {}
        for name, tid, path, p, param, extra, want in cases:
            root = tempfile.mkdtemp(prefix="pta-fg-")
            try:
                ws = ws_for(root, p)
                pc = "stored_xss_marker" if tid == "xss-stored-marker" else None
                ws.gate.decide(ENG, "http_probe", "127.0.0.1", param, pc, "L2",
                               "approve", scope="class")
                body = {"content": "hello", "author": "alice"} if param else {"nick": "x"}
                f = Executor(ws.probe, ws.store, ENG).run(
                    tpl(tid),
                    Target(url=base + path, method="POST", param_path=param,
                           identity_baseline="alice", identity_probe="alice",
                           body_json=body,
                           control_url=(base + extra["control_url"]
                                        if extra.get("control_url") else None)))
                m = f.verdict.get("metrics") or {}
                bits = []
                if "baseline_status" in m:
                    bits.append("baseline=%s probe=%s anon=%s"
                                % (m.get("baseline_status"), m.get("probe_status"),
                                   m.get("anon_status")))
                if "verify_content_type" in m:
                    bits.append("回读=%s marker=%s escaped=%s"
                                % ((m.get("verify_content_type") or "-").split(";")[0],
                                   m.get("marker_in_verify"), m.get("escaped")))
                print("%-12s %-20s %-10s %.2f  %s"
                      % (name, path, f.status, f.confidence, " ".join(bits)))
                print("             %s" % (f.verdict.get("rationale") or "")[:150])
                results[name] = f
                checks.append((name, f.status == want))
            finally:
                pass
        print()

        a = results["A 不校验令牌"]
        b = results["B 校验令牌"]
        c = results["C 匿名也能改"]
        d = results["D 回读原样渲染"]
        e = results["E 回读被转义"]
        checks.append(("A 提到 0.90", a.confidence >= 0.90))
        checks.append(("B 说出「防护在起作用」", "防护" in (b.verdict.get("rationale") or "")))
        checks.append(("C 改判成「缺失授权」", "授权" in (c.verdict.get("rationale") or "")))
        checks.append(("D 认出标签结构", bool((d.verdict.get("metrics") or {}).get("in_tag"))))
        checks.append(("E 认出被转义", bool((e.verdict.get("metrics") or {}).get("escaped"))))

        print("自检：")
        for name, ok in checks:
            print("  [%s] %s" % ("OK" if ok else "!!", name))
        good = all(ok for _, ok in checks)
        print()
        print("结果：%s（摘掉一个头还能改成功才叫没有令牌校验；"
              "写进去还要读回来才算存储型）" % ("OK" if good else "FAIL"))
        return 0 if good else 1
    finally:
        srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
