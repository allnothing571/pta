"""批量读：判的是"能读多少个"，不是"某一个读不读得到"。

同一个站点、同一个模板，只有"服务端怎么管对象"不同：
  A 全开：任意 id 都返回各自的对象      → confirmed 0.90（8/8 可读）
  B 半开：偶数 id 被拒                  → confirmed 0.86（比例不低于一半）
  C 收紧：只有 id=7 是自己那条           → refuted   0.00（对象级授权在起作用）
  D 不看 id：任何 id 都返回同一份         → refuted   0.30（读到的不是各自的对象）

A/B 与 C 的区别不在"能不能读"，而在"能读一片还是只能读一条"；D 是
"看起来全开、其实根本没按 id 查"——这两种在单对象测试里长得一模一样。
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
from typing import Dict, List
from urllib.parse import parse_qsl, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

ENG = "ENG-DEMO-BATCH"
COUNT = 8
CHECKS: List[tuple] = []


class Handler(http.server.BaseHTTPRequestHandler):
    mode = "open"
    seen: List[int] = []

    def do_GET(self):  # noqa: N802
        q = dict(parse_qsl(urlsplit(self.path).query))
        try:
            ident = int(q.get("id") or 0)
        except ValueError:
            ident = 0
        self.seen.append(ident)
        if not self.headers.get("Authorization"):
            return self._send(401, {"error": "unauthorized"})
        if self.mode == "blind":
            # 压根不按 id 查：谁问都回这一份
            return self._send(200, {"id": 0, "owner": "nobody", "total": 0})
        if self.mode == "scoped":
            if ident == 7:
                return self._send(200, {"id": 7, "owner": "alice", "total": 99})
            return self._send(403, {"error": "forbidden"})
        if ident <= 0 or ident >= 1000:
            return self._send(404, {"error": "not found"})
        if self.mode == "partial" and ident % 2 == 0:
            return self._send(403, {"error": "forbidden"})
        return self._send(200, {"id": ident, "owner": "user%d" % ident,
                                "total": ident * 7})

    def _send(self, status: int, payload: Dict[str, object]):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # 静默
        pass


def serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def template():
    raw = [t for t in vhx.TEMPLATES if t["id"] == "idor-batch-sweep"][0]
    raw = json.loads(json.dumps(raw))
    raw["probe"]["batch"]["count"] = COUNT
    return vhx.load(raw)


def workspace(port: int):
    root = tempfile.mkdtemp(prefix="pta-demo-batch-")
    init_workspace(root, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                               allow_private=True, allowed_ports=(port,),
                               rate_per_host=1000, max_requests=200))
    ws = open_workspace(root, dns=DnsPin(resolver=lambda h: ["127.0.0.1"]))
    ws.vault.put("cred/alice/authorization", "Bearer alice")
    return root, ws


def check(cond: bool, msg: str):
    CHECKS.append((bool(cond), msg))
    print("    %s %s" % ("ok  " if cond else "FAIL", msg))


def run_case(title: str, mode: str, port: int, want_status: str,
             want_conf: float, want_reason: str):
    print("[%s]" % title)
    Handler.mode = mode
    Handler.seen = []
    root, ws = workspace(port)
    try:
        f = Executor(ws.probe, ws.store, ENG).run(
            template(),
            Target(url="http://127.0.0.1:%d/api/orders?id=7" % port,
                   identity_baseline="alice", identity_probe="alice"))
        m = f.verdict.get("metrics") or {}
        print("  status=%s conf=%.2f  可读 %s/%s  ratio=%s  requests_used=%d"
              % (f.status, f.confidence, m.get("readable", "-"), m.get("total", "-"),
                 m.get("ratio", "-"), f.requests_used))
        print("  扫的 id：%s" % ", ".join(str(i) for i in Handler.seen[:COUNT + 2]))
        print("  %s" % (f.verdict.get("rationale") or ""))
        print()
        check(f.status == want_status, "状态是 %s" % want_status)
        check(abs(f.confidence - want_conf) < 0.01,
              "置信度 %.2f" % want_conf)
        check(want_reason in (f.verdict.get("rationale") or ""),
              "理由里有「%s」" % want_reason)
        check(999999999 in Handler.seen, "发过 decoy（不存在的对象）")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    print("=" * 78)
    print("批量对象越权：8 个相邻对象，看能读通几个")
    print("=" * 78)
    print()
    srv, port = serve()
    try:
        run_case("A 全开：任意 id 都返回各自的对象", "open", port,
                 "confirmed", 0.90, "一整片不属于它的对象")
        run_case("B 半开：偶数 id 被拒", "partial", port,
                 "confirmed", 0.86, "比例不低于一半")
        run_case("C 收紧：只有自己那条能读", "scoped", port,
                 "refuted", 0.00, "对象级授权")
        run_case("D 不看 id：任何 id 都返回同一份", "blind", port,
                 "refuted", 0.30, "响应与对象 id 无关")
    finally:
        srv.shutdown()

    bad = [m for ok, m in CHECKS if not ok]
    print("-" * 78)
    if bad:
        print("结果：FAIL（%d 项没过：%s）" % (len(bad), "; ".join(bad)))
        return 1
    print("结果：OK（%d 项自检；能读一片才算越权，读了同一份内容不算）" % len(CHECKS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
