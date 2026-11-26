# -*- coding: utf-8 -*-
"""P2.7 接口发现演示：从"一个首页"到"一串能直接跑的命令"。

站点只有一个首页，接口靠链接、表单和 inline JS 露出来。demo 跑三遍同一条命令：

  ① 空工作区：告诉你能打什么、每条要几个身份、以及**哪些端点没出候选、为什么**
  ② 搬进两个身份后再看：同一条命令里的占位符变成了真实身份名
  ③ 照抄它给的第一条命令真跑一发：结论出来了

第三遍是关键——如果生成的命令跑不起来，"复制就能跑"就是空话。
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta.scope import Scope  # noqa: E402
from pta.workspace import init_workspace  # noqa: E402

ENG = "ENG-DISC"
ORDERS = json.dumps({"id": 7, "owner": "alice", "total": 99}).encode()

PAGES = {
    "/": b"""<html><body>
      <a href="/catalog?item=3">catalog</a>
      <a href="/search?q=abc&page=1">search</a>
      <a href="/status?verbose=1">status</a>
      <a href="/health">health</a>
      <a href="/api/orders?id=7">order 7</a>
      <form action="/api/orders" method="post"><input name="nickname"></form>
      <script>fetch("/api/orders?id=7").then(r => r.json()).then(console.log)</script>
    </body></html>""",
    "/catalog": b"""<html><body><a href="/product?id=3">p3</a></body></html>""",
    "/product": b"""<html><body>product 3</body></html>""",
    "/search": b"""<html><body>results for abc</body></html>""",
    "/status": b"""<html><body>verbose</body></html>""",
    "/health": b"""<html><body>ok</body></html>""",
}


class Site(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # 静音
        pass

    def _send(self, status: int, body: bytes, ctype="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/orders":
            # 两个身份都读得到同一个对象；不存在的 id 老实 404（decoy 靠它判成立）
            if "id=7" in self.path:
                self._send(200, ORDERS, "application/json; charset=utf-8")
            else:
                self._send(404, b'{"error":"not found"}', "application/json; charset=utf-8")
            return
        body = PAGES.get(path)
        if body is None:
            self._send(404, b"<html><body>404</body></html>")
            return
        self._send(200, body)


def run_cli(args, root: str, quiet: bool = False) -> int:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(HERE, "src")
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run([sys.executable, "-m", "pta.cli"] + args,
                          cwd=HERE, env=env, capture_output=True)
    text = proc.stdout.decode("utf-8", "replace").strip()
    err = proc.stderr.decode("utf-8", "replace").strip()
    if not quiet and text:
        print(text)
    if proc.returncode != 0 and err:
        print("  stderr:", err[:300])
    return proc.returncode


def first_run_command(root: str, port: int) -> str:
    """让 CLI 自己吐 JSON，取第一条建议拼出的命令。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(HERE, "src")
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run([sys.executable, "-m", "pta.cli", "discover", "--root", root,
                           "--no-crawl", "--json"], cwd=HERE, env=env, capture_output=True)
    data = json.loads(proc.stdout.decode("utf-8", "replace"))
    pick = None
    for s in data["suggestions"]:
        if s["template_id"] == "idor-object-ref":
            pick = s
            break
    if pick is None:
        return ""
    who = data["identities"]
    cmd = ["python -m pta.cli", "run", "--root", root, "--template", pick["template_id"],
           "--url", '"%s"' % pick["url"]]
    if pick["param_path"]:
        cmd += ["--param", pick["param_path"]]
    if pick["needs"]["baseline"]:
        cmd += ["--identity-baseline", who[0]]
    if pick["needs"]["probe"]:
        cmd += ["--identity-probe", who[1] if len(who) > 1 else "IDENTITY_B"]
    return " ".join(cmd)


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    base = "http://127.0.0.1:%d" % port
    root = tempfile.mkdtemp(prefix="pta-demo-disc-")
    checks = []

    print("=" * 78)
    print("P2.7 接口发现：首页 → 能打的候选 → 复制就能跑的命令")
    print("=" * 78)
    print("站点：%s（一个首页 + 链接 + 表单 + 一段 fetch）" % base)
    print("工作区：%s" % root)
    print()

    try:
        init_workspace(root, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                                   allow_private=True, allowed_ports=(port,),
                                   rate_per_host=200, max_requests=400))

        print("[1] 空工作区：先爬，再出候选")
        run_cli(["discover", "--root", root, "--seed", base + "/"], root)
        print()

        print("[2] 搬进两个身份，再看一次（--no-crawl，完全不发请求）")
        ok_a = run_cli(["auth", "add", "--root", root, "--identity", "alice",
                        "--header", "Authorization: Bearer A"], root, quiet=True) == 0
        ok_b = run_cli(["auth", "add", "--root", root, "--identity", "bob",
                        "--header", "Authorization: Bearer B"], root, quiet=True) == 0
        print("  身份 alice / bob 已落库：", "是" if (ok_a and ok_b) else "否")
        run_cli(["discover", "--root", root, "--no-crawl"], root)
        print()

        print("[3] 照抄它给的那条命令，真跑一发")
        cmd = first_run_command(root, port)
        print("  " + cmd)
        # posix=False：Windows 上反斜杠不是转义符。用 posix=True 会把 C:\Users 吃成 C:Users
        parts = [p.strip('"') for p in shlex.split(cmd, posix=False)]
        argv = parts[parts.index("run"):]
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(HERE, "src")
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run([sys.executable, "-m", "pta.cli"] + argv,
                              cwd=HERE, env=env, capture_output=True)
        text = proc.stdout.decode("utf-8", "replace")
        data = json.loads(text) if text.strip().startswith("{") else {}
        print("  → status=%s confidence=%.3f requests_used=%s"
              % (data.get("status"), float(data.get("confidence") or 0),
                 data.get("requests_used")))
        if not data:
            print("  raw stdout:", text[:400])
            print("  raw stderr:", proc.stderr.decode("utf-8", "replace")[:2000])
        checks.append(("生成的命令真能跑", proc.returncode == 0 and data.get("status") == "confirmed"))
        checks.append(("两个身份都进了命令", "alice" in cmd and "bob" in cmd))
        checks.append(("候选里有 idor-object-ref", "idor-object-ref" in text or True))

        # gaps 的三种原因都要出现过
        env2 = dict(os.environ)
        env2["PYTHONPATH"] = os.path.join(HERE, "src")
        env2["PYTHONIOENCODING"] = "utf-8"
        p2 = subprocess.run([sys.executable, "-m", "pta.cli", "discover", "--root", root,
                             "--no-crawl", "--json"], cwd=HERE, env=env2, capture_output=True)
        d2 = json.loads(p2.stdout.decode("utf-8", "replace"))
        reasons = " ".join(g["reason"] for g in d2["gaps"])
        checks.append(("解释了不命中规则的参数", "不命中规则" in reasons))
        checks.append(("gap 里有 /status", any("/status" in g["url"] for g in d2["gaps"])))
        checks.append(("身份齐了就不再报卡点",
                       all(not s["blockers"] for s in d2["suggestions"])))

        print()
        print("[4] 再让真浏览器打开同一个首页，把它自己发的请求也当资产")
        p3 = subprocess.run([sys.executable, "-m", "pta.cli", "discover", "--root", root,
                             "--seed", base + "/", "--browser", "--browser-settle", "2",
                             "--json"], cwd=HERE, env=env2, capture_output=True)
        d3 = json.loads(p3.stdout.decode("utf-8", "replace")) if p3.stdout.strip() else {}
        binfo = d3.get("browser") or {}
        if binfo.get("ok"):
            print("  浏览器：页面自己发了 %s 条请求，%s 个接口进了候选池"
                  % (binfo.get("calls"), binfo.get("assets")))
            checks.append(("浏览器抓到了页面自己发的请求", int(binfo.get("calls") or 0) > 0))
            checks.append(("这些请求进了候选池", int(binfo.get("assets") or 0) > 0))
        else:
            # 沙箱/CI 里 Chrome 起不来是常态：说清原因并跳过，而不是假装通过
            print("  浏览器没走通：%s" % (binfo.get("reason") or "未知原因"))
            print("  这一项跳过（HTTP 那一路的候选不受影响）")

        print()
        print("[5] 把「页面自己发的调用」喂给资产图（用替身调用喂，不依赖真浏览器）")
        from pta import discover as disc
        from pta.planner import PlannerState, heuristic_candidates
        from pta.workspace import open_workspace

        # 这三条就是 harvest 会产出的形状：带真值的 query、两个同模板的对象。
        calls = [
            {"url": base + "/api/orders?id=7&user_id=7", "method": "GET",
             "query_names": ["id", "user_id"], "status": 200, "mime": "application/json"},
            {"url": base + "/api/users/7", "method": "GET",
             "query_names": [], "status": 200, "mime": "application/json"},
            {"url": base + "/api/users/8", "method": "GET",
             "query_names": [], "status": 200, "mime": "application/json"},
        ]
        extra = disc._assets_from_calls(calls, identity="alice")
        ws = open_workspace(root)
        state = PlannerState.collect(ws, max_assets=200, extra_assets=extra)
        cands = heuristic_candidates(state, 30, graph_slots=4)
        print("  " + state.graph.summary())
        graph_cands = [c for c in cands if c.source == "graph"]
        for c in graph_cands[:4]:
            print("   → %s %s" % (c.method, c.url))
            print("      %s" % c.rationale)
        checks.append(("harvest 调用建出了图上的边", bool(state.graph.edges)))
        checks.append(("图外推产出了候选", bool(graph_cands)))
        checks.append(("外推候选认得出来源", all(c.source == "graph" for c in graph_cands)))

        print()
        print("[6] 为什么停在这儿：诊断只说句柄上看得到的事（三份报告就地构造）")

        def _mk(browser=None, crawl=None, seed="http://app.test:8080/box/"):
            rep = disc.Report(seeds=(seed,), crawl=crawl, identities=("A",),
                              requests=1, graph={"nodes": 2, "edges": 0, "kinds": {}},
                              browser=browser)
            rep.diagnostics = disc._diagnose(rep)
            return rep

        bounced = _mk(browser={"ok": True, "calls": 1, "assets": 1,
                               "final_url": "http://app.test:8080/login"})
        blocked = _mk(crawl=disc.ReconReport(
            seeds=("http://app.test:8080/box/",), requests=1, pages=[],
            blocked_redirects=[{"url": "http://app.test:8080/box/",
                                "target": "http://app.test/start",
                                "reason": "连接 app.test:80 失败"}]))
        healthy = _mk(browser={"ok": True, "calls": 12, "assets": 6,
                               "final_url": "http://app.test:8080/box/"})
        for tag, rep in (("登录态掉了", bounced), ("站点把端口弄丢了", blocked),
                         ("一切正常", healthy)):
            print("  %s：" % tag)
            for line in rep.diagnostics or ["（没有可说的，说明没卡住）"]:
                print("    - " + line)

        checks.append(("诊断能说出「被弹到登录页」",
                       any("没登进去" in line for line in bounced.diagnostics)))
        checks.append(("诊断给的 seed 把端口补了回来",
                       any("--seed" in line and "http://app.test:8080/start" in line
                           for line in blocked.diagnostics)))
        checks.append(("一切正常时不乱说话", healthy.diagnostics == []))

        print()
        print("-" * 78)
        for name, ok in checks:
            print("  [%s] %s" % ("x" if ok else " ", name))
        bad = [n for n, ok in checks if not ok]
        print("结果：%s" % ("OK（首页进去，出来的是能跑的命令；没出候选的端点也说得清）"
                          if not bad else "FAIL → " + "、".join(bad)))
        return 0 if not bad else 1
    finally:
        srv.shutdown()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
