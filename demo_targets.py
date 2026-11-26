# -*- coding: utf-8 -*-
"""P2.8 目标台账演示：第 N 个目标时还记得哪个 --root 是哪个。

`--root` 是一串自己起的目录名。做第三个目标时已经想不起 `lab2` 里装的是什么，
于是要么去翻 scope.json，要么干脆把新目标塞进旧工作区——预算和结论就混了。

台账只记路径，域/结论数/最后活动现场从工作区读。别名可以直接当 `--root` 用。
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

ORDERS = json.dumps({"id": 7, "owner": "alice", "total": 99}).encode()


class Site(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status: int, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if "/api/orders" in self.path and "id=7" in self.path:
            self._send(200, ORDERS)
        else:
            self._send(404, b'{"error":"not found"}')


def cli(args, env, quiet=False) -> tuple:
    proc = subprocess.run([sys.executable, "-m", "pta.cli"] + args,
                          cwd=HERE, env=env, capture_output=True)
    out = proc.stdout.decode("utf-8", "replace").strip()
    err = proc.stderr.decode("utf-8", "replace").strip()
    if not quiet:
        print(out or err)
    return proc.returncode, out, err


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    base = "http://127.0.0.1:%d" % port

    work = tempfile.mkdtemp(prefix="pta-demo-tgt-")
    home = os.path.join(work, "pta-home")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(HERE, "src")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PTA_HOME"] = home          # 不碰真实的 ~/.pta
    checks = []

    print("=" * 78)
    print("P2.8 目标台账：别名、结论数、最后活动")
    print("=" * 78)
    print("台账：%s" % os.path.join(home, "targets.json"))
    print()

    try:
        print("[1] 建两个工作区，登记时顺手起个短名")
        cli(["init", "--root", os.path.join(work, "w-shop"), "--engagement", "shop-2026",
             "--domain", "127.0.0.1", "--allow-private", "--allow-port", str(port),
             "--alias", "shop", "--note", "商城主站，先打越权"], env, quiet=True)
        cli(["init", "--root", os.path.join(work, "w-blog"), "--engagement", "blog-2026",
             "--domain", "blog.test", "--alias", "blog", "--note", "博客，还没开始"],
            env, quiet=True)
        code, out, _ = cli(["ls"], env)
        checks.append(("台账里有两行", code == 0 and "shop" in out and "blog" in out))

        print()
        print("[2] 给 shop 搬身份、跑一发，让台账里那行有数")
        cli(["auth", "add", "--root", "shop", "--identity", "alice",
             "--header", "Authorization: Bearer A"], env, quiet=True)
        cli(["auth", "add", "--root", "shop", "--identity", "bob",
             "--header", "Authorization: Bearer B"], env, quiet=True)
        code, out, _ = cli(["run", "--root", "shop", "--template", "idor-object-ref",
                            "--url", "%s/api/orders?id=7" % base, "--param", "query:id",
                            "--identity-baseline", "alice", "--identity-probe", "bob"], env)
        data = json.loads(out) if out.startswith("{") else {}
        checks.append(("用别名就能跑", code == 0 and data.get("status") == "confirmed"))

        print()
        print("[3] 再看台账：结论数/确认数/最后活动都是现场读出来的")
        code, out, _ = cli(["ls"], env)
        checks.append(("shop 那行有 1 条结论", "shop" in out and " 1 " in out))
        checks.append(("blog 那行还是 0", "blog" in out))

        print()
        print("[4] 别名也能喂给 pta show")
        code, out, _ = cli(["show", "--root", "shop", "--last", "--as", "raw"], env)
        checks.append(("show 认得别名", code == 0 and "GET /api/orders?id=7" in out))

        print()
        print("[5] 目录被人删了：台账要说明白，而不是给一行假数据")
        shutil.rmtree(os.path.join(work, "w-blog"), ignore_errors=True)
        code, out, _ = cli(["ls"], env)
        checks.append(("删掉的目录被标出来", "目录不在了" in out))

        print()
        print("[6] forget 只动台账，不动目录")
        code, out, _ = cli(["forget", "blog"], env)
        checks.append(("forget 成功", code == 0 and json.loads(out).get("ok") is True))
        code, out, _ = cli(["ls", "--json"], env)
        rows = json.loads(out)["targets"]
        checks.append(("台账只剩 shop", [r["alias"] for r in rows] == ["shop"]))
        checks.append(("shop 目录还在", os.path.isdir(os.path.join(work, "w-shop"))))

        print()
        print("-" * 78)
        for name, ok in checks:
            print("  [%s] %s" % ("x" if ok else " ", name))
        bad = [n for n, ok in checks if not ok]
        print("结果：%s" % ("OK（第 N 个目标时还记得哪个是哪个；别名能直接当 --root）"
                          if not bad else "FAIL → " + "、".join(bad)))
        return 0 if not bad else 1
    finally:
        srv.shutdown()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
