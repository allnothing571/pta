"""业务逻辑边界演示：越界数值被接受（负数入账 / 超量入库）。

同一个模板，同一个请求形状，只有服务端怎么处理那个数不同：
  A. 负数照单全收       → confirmed：回读里真的是 -100
  B. 金额 <= 0 返回 422 → refuted：范围校验在起作用
  C. 负数被改成 0 再存  → refuted：接口回 200，但存下来的不是那个值
  D. 数量 999999999     → confirmed：同路径 GET 回读，库存就是那个数

第三种最值得看：它是"接口接受 ≠ 值被存下来"这条判据唯一能分开的情形。
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

from pta import vhx  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

ENG = "ENG-LOGIC"
PUBLIC_IP = "127.0.0.1"

STATE = {"balance": 1000, "last_amount": None, "stock": 5, "seen": []}

PAGES = {
    "vuln": "/api/transfer",
    "strict": "/api/transfer-strict",
    "clamp": "/api/transfer-clamp",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # 静默
        pass

    def _json(self, status: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self) -> bool:
        if not self.headers.get("Authorization"):
            self._json(401, {"error": "unauthorized"})
            return False
        return True

    def do_GET(self) -> None:
        if not self._auth():
            return
        path = self.path.split("?")[0]
        if path == "/api/balance":
            return self._json(200, {"balance": STATE["balance"],
                                    "last_amount": STATE["last_amount"]})
        if path == "/api/stock":
            return self._json(200, {"sku": "A1", "quantity": STATE["stock"]})
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._auth():
            return
        n = int(self.headers.get("Content-Length") or 0)
        data = json.loads((self.rfile.read(n) or b"{}").decode() or "{}")
        path = self.path.split("?")[0]

        if path == "/api/stock":
            qty = data.get("quantity")
            STATE["seen"].append(("stock", qty, type(qty).__name__))
            STATE["stock"] = qty
            return self._json(200, {"ok": True, "quantity": qty})

        mode = {v: k for k, v in PAGES.items()}.get(path)
        if mode is None:
            return self._json(404, {"error": "not found"})
        amount = data.get("amount")
        STATE["seen"].append((mode, amount, type(amount).__name__))
        if mode == "strict" and not (isinstance(amount, int) and amount > 0):
            return self._json(422, {"error": "amount must be positive"})
        if mode == "clamp" and isinstance(amount, int) and amount < 0:
            amount = 0  # 静默夹紧：回 200，但存下来的不是原值
        STATE["last_amount"] = amount
        STATE["balance"] += amount if isinstance(amount, int) else 0
        return self._json(200, {"ok": True, "amount": amount})


def serve() -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _ws(port: int):
    root = tempfile.mkdtemp(prefix="pta-demo-logic-")
    init_workspace(root, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                               allow_private=True, allowed_ports=(port,),
                               rate_per_host=200, max_requests=200))
    ws = open_workspace(root, dns=DnsPin(resolver=lambda h: ["127.0.0.1"]))
    ws.vault.put("cred/A/authorization", "Bearer A")
    ws.gate.decide(ENG, "http_probe", "127.0.0.1", "body:amount",
                   "negative_number", "L2", "approve", scope="class")
    ws.gate.decide(ENG, "http_probe", "127.0.0.1", "body:quantity",
                   "huge_number", "L2", "approve", scope="class")
    ws._demo_root = root  # type: ignore[attr-defined]
    return ws


def _tpl(tid: str):
    return vhx.load([t for t in vhx.TEMPLATES if t["id"] == tid][0])


def run_case(title: str, port: int, template_id: str, target: Target):
    ws = _ws(port)
    try:
        f = Executor(ws.probe, ws.store, ENG).run(_tpl(template_id), target)
        m = f.verdict.get("metrics") or {}
        print("  %-12s status=%-9s conf=%.2f  %s" %
              (title, f.status, f.confidence, f.verdict.get("rationale", "")[:60]))
        print("      metrics: baseline=%s probe=%s readback=%s" %
              (m.get("baseline_status"), m.get("probe_status"),
               m.get("readback_status")))
        return f
    finally:
        shutil.rmtree(getattr(ws, "_demo_root", ""), ignore_errors=True)


def main() -> int:
    srv = serve()
    port = srv.server_address[1]
    base = "http://127.0.0.1:%d" % port
    checks = []

    def check(name: str, ok: bool) -> None:
        checks.append((name, bool(ok)))
        print("  [%s] %s" % ("OK" if ok else "!!", name))

    print("=" * 78)
    print("业务逻辑边界：接口接受了，值真的进去了吗（端口 %d）" % port)
    print("=" * 78)

    print("[A] 负数照单全收")
    fa = run_case("负数入账", port, "logic-negative-amount",
                  Target(url=base + PAGES["vuln"], method="POST",
                         param_path="body:amount", identity_baseline="A",
                         identity_probe="A", body_json={"to": "bob", "amount": 1},
                         verify_url=base + "/api/balance"))
    check("A 判 confirmed", fa.status == "confirmed")
    check("A 置信度 ≥0.85", fa.confidence >= 0.85)
    check("A 服务端收到的是 JSON 数字 -100",
          any(k == "vuln" and v == -100 and t == "int" for k, v, t in STATE["seen"]))
    check("A 回读 last_amount == -100", STATE["last_amount"] == -100)

    print("[B] 金额 <= 0 直接拒绝")
    fb = run_case("422 拒绝", port, "logic-negative-amount",
                  Target(url=base + PAGES["strict"], method="POST",
                         param_path="body:amount", identity_baseline="A",
                         identity_probe="A", body_json={"to": "bob", "amount": 1},
                         verify_url=base + "/api/balance"))
    check("B 判 refuted", fb.status == "refuted")
    check("B 说的是「范围校验」", "范围校验" in fb.verdict.get("rationale", ""))

    print("[C] 接口回 200，但负数被静默改成 0")
    STATE["last_amount"] = None
    fc = run_case("静默夹紧", port, "logic-negative-amount",
                  Target(url=base + PAGES["clamp"], method="POST",
                         param_path="body:amount", identity_baseline="A",
                         identity_probe="A", body_json={"to": "bob", "amount": 1},
                         verify_url=base + "/api/balance"))
    check("C 判 refuted", fc.status == "refuted")
    check("C 说的是「夹紧」", "夹紧" in fc.verdict.get("rationale", ""))
    check("C 存下来的是 0 而不是 -100", STATE["last_amount"] == 0)

    print("[D] 数量 999999999（同路径 GET 回读，不给 --verify-url）")
    fd = run_case("超量入库", port, "logic-quantity-overflow",
                  Target(url=base + "/api/stock", method="POST",
                         param_path="body:quantity", identity_baseline="A",
                         identity_probe="A", body_json={"sku": "A1", "quantity": 1}))
    check("D 判 confirmed", fd.status == "confirmed")
    check("D 置信度 ≥0.85", fd.confidence >= 0.85)
    check("D 库存真的被写成 999999999", STATE["stock"] == 999999999)
    check("D 服务端收到的是 JSON 数字",
          any(k == "stock" and v == 999999999 and t == "int" for k, v, t in STATE["seen"]))

    srv.shutdown()
    bad = [n for n, ok in checks if not ok]
    print()
    if bad:
        print("结果：FAIL —— %s" % "；".join(bad))
        return 1
    print("结果：OK（%d 项自检：接受 ≠ 存下来，夹紧要看成没成）" % len(checks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
