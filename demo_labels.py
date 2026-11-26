# -*- coding: utf-8 -*-
"""P2.6 人工标注演示：判错了怎么办。

这里故意让工具判错一次，因为这一层的价值就在"判错之后"。

  A. 公开商品页 /api/products/7
     谁都能读、任何登录态都返回同一份 —— 工具看到的证据完全成立：
     alice 读到、bob 也读到、decoy（id=999999999）404。相似度 1.000。
     于是它判 confirmed。但人一眼就知道这是误报：商品详情页本来就是公开的，
     「两个身份读到同一份」不等于「内容属于某个人」。
     → 标 fp。状态改 refuted，置信度 1.000 原样留着（那是系统当时的判断）。

  B. 订单页 /api/orders/7
     同样两身份都能读，但这条真的是别人的订单（owner=alice，bob 在读）。
     → 标 tp。

  C. stats 按模板算误报率：分母只算人看过的那些，没标过显示「—」不是 0%。

  D. 撤销标注：恢复系统原判，verdict 里不留痕。
"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import threading
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import cli  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402
from pta import vhx  # noqa: E402

ENG = "ENG-DEMO-LAB"

PRODUCT = {"id": 7, "name": "公开商品", "price": 99}
ORDER = {"id": 7, "owner": "alice", "total": 99}


class Site(BaseHTTPRequestHandler):
    """两条接口都"两个身份都能读"，区别只在语义：
    products 是公开资源，orders 是别人的订单。工具分不出这个差别，人要能。"""

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            body, status = b"ok", 200
        elif path.startswith("/api/products/"):
            oid = path.rsplit("/", 1)[-1]
            body, status = ((json.dumps(PRODUCT).encode(), 200) if oid == "7"
                            else (b'{"error":"not found"}', 404))
        elif path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[-1]
            body, status = ((json.dumps(ORDER).encode(), 200) if oid == "7"
                            else (b'{"error":"not found"}', 404))
        else:
            body, status = b'{"error":"not found"}', 404
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def call(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(argv)
    return code, buf.getvalue()


def judge(ws, base, path):
    tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == "idor-object-ref"][0])
    return Executor(ws.probe, ws.store, ENG).run(
        tpl, Target(url="%s%s" % (base, path), identity_baseline="alice",
                    identity_probe="bob"))


def main():
    srv = serve()
    port = srv.server_address[1]
    base = "http://127.0.0.1:%d" % port
    root = tempfile.mkdtemp(prefix="pta-demo-label-")
    try:
        init_workspace(root, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                                   allow_private=True, allowed_ports=(port,),
                                   rate_per_host=200, max_requests=200))
        ws = open_workspace(root, dns=DnsPin(resolver=lambda h: ["127.0.0.1"]))
        ws.vault.put("cred/alice/authorization", "Bearer alice-token")
        ws.vault.put("cred/bob/authorization", "Bearer bob-token")

        print("=" * 78)
        print("P2.6 人工标注：判错了之后留下什么")
        print("=" * 78)
        print("站点：%s（两条接口两个身份都能读，语义完全不同）" % base)
        print()

        print("① 公开商品页：工具判 confirmed，人一看是误报")
        f1 = judge(ws, base, "/api/products/7")
        print("    /api/products/7  → %s  置信度 %.3f  相似度 %.3f"
              % (f1.status, f1.confidence, f1.verdict["metrics"]["similarity"]))
        print("    为什么它敢判：alice 读到、bob 也读到、decoy 404 —— 证据链是齐的。")
        print("    为什么是误报：「两个身份读到同一份」不等于「这份内容归某个人」。")
        print()

        print("② 标 fp")
        code, out = call(["mark", "--root", root, f1.id, "--fp",
                          "--by", "yg", "--note", "商品详情页本来就是公开资源，不是越权"])
        print("    " + out.strip().replace("\n", "\n    "))
        print()

        print("③ 订单页：这一条是真洞，标 tp")
        f2 = judge(ws, base, "/api/orders/7")
        print("    /api/orders/7    → %s  置信度 %.3f" % (f2.status, f2.confidence))
        code, out = call(["mark", "--root", root, f2.id, "--tp",
                          "--note", "owner=alice，bob 读到了别人的订单"])
        print("    " + out.strip().replace("\n", "\n    "))
        print()

        print("④ 按模板看误报率（分母只算人看过的）")
        code, out = call(["stats", "--root", root])
        print("    " + out.strip().replace("\n", "\n    "))
        print()

        print("⑤ 撤销刚才那条 fp：恢复系统原判")
        code, out = call(["mark", "--root", root, f1.id, "--clear"])
        print("    " + out.strip())
        code, out = call(["labels", "--root", root])
        print("    标注历史仍然留着（改判本身是信息）：")
        print("    " + out.strip().replace("\n", "\n    "))
        print()

        # 自检
        ws2 = open_workspace(root)
        row = ws2.store.get_finding(f1.id)
        verdict = json.loads(row["verdict_json"])
        f1_confidence = float(f1.confidence)
        checks = [
            ("撤销后状态回到系统原判 confirmed", row["status"] == "confirmed"),
            ("撤销后 human_label 已清掉", "human_label" not in verdict),
            ("标注没动过置信度（%.3f 还是 %.3f）" % (f1_confidence, f1_confidence),
             abs(float(row["confidence"]) - f1_confidence) < 1e-9),
            ("判定指标还在，能复盘", "similarity" in verdict.get("metrics", {})),
            ("两次标注都留在库里", len(ws2.store.labels(ENG)) == 2),
            ("角色表还在，pta show 不用猜", "probe" in (verdict.get("roles") or {}).values()),
        ]
        print("自检：")
        ok = True
        for name, passed in checks:
            print("  [%s] %s" % ("OK  " if passed else "FAIL", name))
            ok = ok and passed
        print()
        print("结果：%s" % ("OK（判错能标、原判能查、能变成回归样本）" if ok else "FAIL"))
    finally:
        srv.shutdown()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
