"""P1 演示：一次 run 把 模板 → 动作 → 证据 → 判定 → finding 全串起来。

python demo_run.py
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pta import vhx  # noqa: E402
from pta.api import make_server  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockRoute, MockTransport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
OBJ = b'{"id":7,"email":"alice@corp.test","phone":"13800000000","role":"user"}'


def routes():
    return [
        MockRoute("GET", "shop.test", "/rest/user/7", 200, (("Content-Type", "application/json"),),
                  OBJ, identity="Bearer A"),
        MockRoute("GET", "shop.test", "/rest/user/7", 200, (("Content-Type", "application/json"),),
                  OBJ, identity="Bearer B"),
        MockRoute("GET", "shop.test", "/api/search", 200, (("Content-Type", "text/html"),),
                  b"<html><body>2 results for q</body></html>"),
        MockRoute("GET", "shop.test", "/.git/HEAD", 200, (("Content-Type", "text/plain"),),
                  b"ref: refs/heads/release\n"),
        MockRoute("GET", "shop.test", "/.env", 200, (("Content-Type", "text/html"),),
                  b'<!doctype html><html><div id="root"></div><script src="/app.js"></script></html>'),
    ]


def tpl(tid):
    return vhx.load({t["id"]: t for t in vhx.TEMPLATES}[tid])


def main() -> int:
    root = tempfile.mkdtemp(prefix="pta-demo-")
    init_workspace(root, Scope(engagement_id="DEMO-1", domains=("shop.test",),
                               allow_private=True, rate_per_host=200, max_requests=200))
    ws = open_workspace(root, transport=MockTransport(routes()),
                        dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
    ws.vault.put("cred/A/authorization", "Bearer A")
    ws.vault.put("cred/B/authorization", "Bearer B")
    eng = Executor(ws.probe, ws.store, "DEMO-1")
    q = ws.bus.subscribe()

    cases = [
        ("idor-object-ref", Target(url="http://shop.test/rest/user/7",
                                   identity_baseline="A", identity_probe="B"), "越权读同对象"),
        ("idor-object-ref", Target(url="http://shop.test/rest/user/7",
                                   identity_baseline="A", identity_probe="A"), "同身份对照（应否定）"),
        ("info-disclosure-artifact", Target(url="http://shop.test/.git/HEAD"), "git 元数据泄露"),
        ("info-disclosure-artifact", Target(url="http://shop.test/.env"), "SPA 回退（应否定）"),
        ("sqli-error-boolean", Target(url="http://shop.test/api/search", param_path="query:q",
                                      identity_baseline="A", identity_probe="A"), "SQL 报错注入（应否定）"),
    ]

    print("%-26s %-12s %-6s %-6s %s" % ("模板", "结论", "置信度", "请求", "停止原因"))
    print("-" * 78)
    findings = []
    for tid, target, note in cases:
        f = eng.run(tpl(tid), target)
        findings.append(f)
        print("%-26s %-12s %-6.3f %-6d %s   %s" % (
            tid, f.status, f.confidence, f.requests_used, f.stop_reason or "-", note))

    events = []
    while True:
        try:
            events.append(q.get_nowait())
        except queue.Empty:
            break
    print("\nSSE 事件：%s" % ", ".join(sorted({e["type"] for e in events})))

    # 走 HTTP API 再跑一次，证明 /api/run 可用（异步：202 + SSE 收结果）
    httpd, _ = make_server(ws, bus=ws.bus, port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    body = json.dumps({"template_id": "idor-object-ref",
                       "url": "http://shop.test/rest/user/7",
                       "identity_baseline": "A", "identity_probe": "B"}).encode()
    q = ws.bus.subscribe()
    req = urllib.request.Request("http://127.0.0.1:%d/api/run" % httpd.server_port, data=body,
                                 method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        accepted = json.loads(r.read().decode())
    done = None
    while done is None:
        ev = q.get(timeout=15)
        if ev["type"] in ("run_finished", "run_failed") and ev.get("run_id") == accepted["run_id"]:
            done = ev
    httpd.shutdown()
    if done["type"] == "run_failed":
        print("POST /api/run → 失败：%s" % done["reason"])
        return 1
    print("POST /api/run → 202 run_id=%s  结论 %s %.3f finding=%s" % (
        accepted["run_id"], done["status"], done["confidence"], done["finding_id"][:12]))

    rows = ws.store.list_findings("DEMO-1")
    print("findings 落库：%d 条；证据：%d 条" % (len(rows), len(ws.store.list_evidence("DEMO-1"))))
    print("工作区：%s" % root)
    if os.environ.get("PTA_KEEP") != "1":
        shutil.rmtree(root, ignore_errors=True)
    ok = (findings[0].status == "confirmed" and findings[1].status == "refuted"
          and findings[2].status == "confirmed" and findings[3].status == "refuted"
          and findings[4].status == "refuted")
    print("\n演示结果：%s" % ("OK（命中/否定都判对）" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
