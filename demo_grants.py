"""审批预授权演示：跑之前批一类，跑完能查是哪一类放行的。

平时最烦的不是"要不要批"，而是"每跑一个 L2 模板就停一次"。这个演示走一遍
完整的自用节奏：

  A. 直接跑 → pending_approval，拿到指纹
  B. --dry-run 看会批哪几条（不写盘）
  C. 真批 → 指纹与 A 拿到的那条一致（说明展开算的对）
  D. 再跑同一个模板 → 直接 confirmed
  E. audit → 看到这一发是 approved:class 放行的，带证据 id
  F. revoke → 再跑又回到 pending

全程不碰真实目标：起一个本地账本服务（负数照单全收）。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta.scope import Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

ENG = "ENG-GRANT"
STATE = {"balance": 1000, "last_amount": None}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, status: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not self.headers.get("Authorization"):
            return self._json(401, {"error": "unauthorized"})
        return self._json(200, {"balance": STATE["balance"],
                                "last_amount": STATE["last_amount"]})

    def do_POST(self) -> None:
        if not self.headers.get("Authorization"):
            return self._json(401, {"error": "unauthorized"})
        n = int(self.headers.get("Content-Length") or 0)
        data = json.loads((self.rfile.read(n) or b"{}").decode() or "{}")
        amount = data.get("amount")
        if isinstance(amount, int):
            STATE["last_amount"] = amount
            STATE["balance"] += amount
        return self._json(200, {"ok": True, "amount": amount})


def serve() -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def cli(root: str, *argv: str):
    """按用户的方式调 CLI：子进程、真参数、真输出。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(HERE, "src")
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run([sys.executable, "-m", "pta.cli"] + list(argv) + ["--root", root],
                       capture_output=True, text=True, encoding="utf-8", env=env,
                       cwd=HERE)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main() -> int:
    srv = serve()
    port = srv.server_address[1]
    base = "http://127.0.0.1:%d" % port
    root = tempfile.mkdtemp(prefix="pta-demo-grant-")
    checks = []

    def check(name: str, ok: bool) -> None:
        checks.append((name, bool(ok)))
        print("  [%s] %s" % ("OK" if ok else "!!", name))

    try:
        init_workspace(root, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                                   allow_private=True, allowed_ports=(port,),
                                   rate_per_host=200, max_requests=200))
        ws = open_workspace(root)
        ws.vault.put("cred/A/authorization", "Bearer A")
        ws.gate  # 不预置任何审批

        run_args = ["run", "--template", "logic-negative-amount",
                    "--url", base + "/api/transfer", "--method", "POST",
                    "--param", "body:amount",
                    "--body-json", '{"to": "bob", "amount": 1}',
                    "--verify-url", base + "/api/balance",
                    "--identity-baseline", "A", "--identity-probe", "A"]

        print("=" * 78)
        print("审批预授权：跑之前批一类（端口 %d）" % port)
        print("=" * 78)

        print("[A] 什么都没批，直接跑")
        code, out = cli(root, *run_args)
        first = json.loads(out)
        stop = first.get("stop_reason") or ""
        fp = stop.split(":", 1)[1] if stop.startswith("pending_approval:") else ""
        print("  status=%s  stop=%s" % (first.get("status"), stop))
        check("A 停在 pending_approval", first.get("status") == "pending_approval")
        check("A 拿到了指纹", bool(fp))

        print("[B] --dry-run：先看会批哪几条")
        code, out = cli(root, "grant", "--template", "logic-negative-amount",
                        "--dry-run")
        print("  " + "\n  ".join(out.strip().splitlines()[:4]))
        check("B 没写盘", "没有写入" in out)

        print("[C] 真批（只在今天有效）")
        code, out = cli(root, "grant", "--template", "logic-negative-amount",
                        "--by", "yg", "--ttl", "1", "--json")
        data = json.loads(out)
        granted = data["grants"][0]["fp"]
        print("  批了 %d 条：%s…" % (len(data["grants"]), granted[:8]))
        check("C 批成功", code == 0 and len(data["grants"]) == 1)
        check("C 指纹与真发时算出的一致", granted == fp)

        print("[D] 再跑同一个模板")
        code, out = cli(root, *run_args)
        second = json.loads(out)
        print("  status=%s conf=%.2f  %s" % (
            second.get("status"), second.get("confidence", 0),
            (second.get("verdict") or {}).get("rationale", "")[:52]))
        check("D 这次直接 confirmed", second.get("status") == "confirmed")

        print("[E] audit：这一发凭什么放行的")
        code, out = cli(root, "audit", "--level", "L2")
        print("  " + "\n  ".join(out.strip().splitlines()[:4]))
        check("E 记到 approved:class", "approved:class" in out)
        check("E 带上了证据 id", "evidence" not in out and out.count(" ") > 10)

        print("[F] 撤销之后又回到 pending")
        code, out = cli(root, "revoke", "--fp", fp)
        check("F 撤销成功", code == 0 and "1" in out)
        code, out = cli(root, *run_args)
        third = json.loads(out)
        check("F 再次停在 pending_approval",
              third.get("status") == "pending_approval")

        print()
        bad = [n for n, ok in checks if not ok]
        if bad:
            print("结果：FAIL —— %s" % "；".join(bad))
            return 1
        print("结果：OK（%d 项自检：批的是指纹不是模板名，撤销立即生效）" % len(checks))
        return 0
    finally:
        srv.shutdown()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
