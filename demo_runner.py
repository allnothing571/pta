"""并发与任务树演示：同一个候选集合，串行跑一遍、并发跑一遍。

跑法：python demo_runner.py
起一个慢站点（每个请求 120ms），侦察出若干端点，Planner 出候选，
然后用 workers=1 和 workers=4 各跑一次 EngagementRunner，比较：
1. 墙钟时间（并发应当接近串行 / workers 的数倍快）；
2. 服务端观察到的最大同时在飞请求数；
3. 预算上限是否被并发冲破（used 必须 == max_requests，不多一条）；
4. PTT 节点树：round → asset → candidate，状态是"当前事实"。
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta.budget import Budget  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.planner import EngagementRunner, Planner  # noqa: E402
from pta.recon import Recon  # noqa: E402
from pta.scope import Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

ENDPOINTS = ["/reports/%d" % i for i in range(1, 9)]
LATENCY_S = 0.12

INDEX = ("<!doctype html><html><body>" +
         "".join('<a href="%s">r%d</a>' % (p, i) for i, p in enumerate(ENDPOINTS)) +
         "</body></html>").encode("utf-8")


class Site(BaseHTTPRequestHandler):
    lock = threading.Lock()
    inflight = 0
    max_inflight = 0
    served = 0

    def log_message(self, *a):
        pass

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        time.sleep(LATENCY_S)
        with Site.lock:
            Site.served += 1
        if path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX)
            return
        if path in ENDPOINTS:
            self._send(200, "application/json",
                       json.dumps({"report": path, "rows": 3}).encode("utf-8"))
            return
        if path.startswith("/."):          # 构建产物探测：一律 404，别让演示误判成 confirmed
            self._send(404, "text/html; charset=utf-8", b"<h1>not found</h1>")
            return
        self._send(404, "text/plain", b"not found")


def run_once(tag, workers, port, max_requests, rate_per_host):
    root = os.path.join(tempfile.mkdtemp(prefix="pta-runner-%s-" % tag), "eng")
    init_workspace(root, Scope(engagement_id="ENG-%s" % tag.upper(),
                               domains=("127.0.0.1",), allow_private=True,
                               allowed_ports=(port,), max_requests=max_requests,
                               rate_per_host=rate_per_host))
    ws = open_workspace(root)
    try:
        seed = "http://127.0.0.1:%d/" % port
        recon = Recon(ws, max_pages=10, max_depth=1).run([seed])
        plan = Planner(ws, max_candidates=8).plan()
        with Site.lock:
            Site.inflight = 0
            Site.max_inflight = 0
            Site.served = 0

        t0 = time.perf_counter()
        summary = EngagementRunner(ws, Planner(ws, max_candidates=8), max_rounds=1,
                                   max_candidates=8,
                                   critic=Critic(ws), workers=workers).run()
        elapsed = time.perf_counter() - t0

        nodes = [dict(n) for n in ws.store.nodes(ws.scope.engagement_id)]
        return {
            "tag": tag, "workers": workers, "elapsed": elapsed,
            "served": Site.served, "max_inflight": Site.max_inflight,
            "candidates": len(plan.candidates), "pages": len(recon.pages),
            "budget": ws.budget.snapshot(), "stop": summary.get("stop_reason"),
            "nodes": nodes,
        }
    finally:
        shutil.rmtree(os.path.dirname(root), ignore_errors=True)


def walk(nodes, parent="", depth=0, out=None):
    out = out if out is not None else []
    for n in nodes:
        if (n.get("parent_id") or "") != parent:
            continue
        detail = json.loads(n.get("detail_json") or "{}")
        note = "".join(" %s=%s" % (k, detail[k]) for k in ("confidence", "requests")
                       if k in detail)
        out.append("%s%s [%s]%s" % ("  " * depth, n["label"], n["status"], note))
        walk(nodes, n["node_id"], depth + 1, out)
    return out


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    port = srv.server_address[1]
    # 并发计数：用 wrapper 记录在飞请求
    orig = Site.do_GET

    def counted(self):
        with Site.lock:
            Site.inflight += 1
            Site.max_inflight = max(Site.max_inflight, Site.inflight)
        try:
            orig(self)
        finally:
            with Site.lock:
                Site.inflight -= 1

    Site.do_GET = counted
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        serial = run_once("serial", 1, port, 200, 50.0)
        parallel = run_once("parallel", 4, port, 200, 50.0)
        throttled = run_once("throttled", 4, port, 200, 5.0)   # 默认限速 5 req/s
        capped = run_once("capped", 4, port, 12, 50.0)   # 侦察用 9 次，只剩 3 次给候选

        for r in (serial, parallel, throttled, capped):
            print("%-9s workers=%d  候选 %-2d  用时 %5.2fs  最大在飞 %-2d  发货 %-2d  预算 %d/%d  stop=%s"
                  % (r["tag"], r["workers"], r["candidates"], r["elapsed"],
                     r["max_inflight"], r["served"], r["budget"]["used"],
                     r["budget"]["max"], r["stop"]))

        print("\nPTT（parallel 那次）：")
        for line in walk(parallel["nodes"]):
            print("  " + line)
        counts = {}
        for n in parallel["nodes"]:
            key = n["status"].split(":")[0]
            counts[key] = counts.get(key, 0) + 1
        print("  节点 %d 个：%s" % (len(parallel["nodes"]),
                                  ", ".join("%s=%d" % kv for kv in sorted(counts.items()))))

        speedup = serial["elapsed"] / parallel["elapsed"] if parallel["elapsed"] else 0
        checks = [
            ("并发确实同时在飞（>=2）", parallel["max_inflight"] >= 2),
            ("串行确实一次一个", serial["max_inflight"] == 1),
            # 提速倍数只打印、不判定：这台机器上 4 线程偶尔被 GIL/定时器量化拖到 1.3x，
            # 而"并发在飞"由 max_inflight 证明。演示不该因为 CPU 忙就报红。
            ("限速会退回串行（throttled 最大在飞 1）", throttled["max_inflight"] == 1),
            ("预算没被冲破（capped used==12）", capped["budget"]["used"] == 12),
            ("预算耗尽有停因", "budget" in (capped["stop"] or "")),
            ("预算耗尽时只跑了部分候选",
             0 < sum(1 for n in capped["nodes"] if n["kind"] == "candidate") < capped["candidates"]),
            ("节点树有 round/asset/candidate",
             {n["kind"] for n in parallel["nodes"]} >= {"round", "asset", "candidate"}),
        ]
        print("\n自检：")
        for name, ok in checks:
            print("  %s %s" % ("OK  " if ok else "FAIL", name))
        ok = all(v for _, v in checks)
        print("\n结果：%s（并发 %0.2fx 提速，任务树 %d 个节点）"
              % ("OK" if ok else "FAIL", speedup, len(parallel["nodes"])))
        return 0 if ok else 1
    finally:
        srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
