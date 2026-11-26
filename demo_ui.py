"""操作台演示：把界面依赖的每个接口跑一遍，并把四个面板打印成文本。

不打开浏览器也能验收：脚本用真 http.server + 真 urllib 走一遍
  state → 审批 → 证据详情 → 对比 → 异步跑模板 → 审计日志
每一步都断言"界面需要的字段真的在"，最后一行必须是 OK。

想在人肉浏览器里点：python demo_ui.py --serve  （默认 127.0.0.1:8765）
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pta.api import make_server                      # noqa: E402
from pta.probe import ProbeRequest                   # noqa: E402
from pta.scope import DnsPin, Scope                  # noqa: E402
from pta.transport import MockRoute, MockTransport   # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"

OBJECT_A = b'{"id":1,"email":"alice@example.com","role":"user","tenant":"acme"}'
OBJECT_B = b'{"id":1,"email":"alice@example.com","role":"admin","tenant":"acme"}'

ROUTES = [
    MockRoute("GET", "app.test", "/api/users/1", 200,
              (("Content-Type", "application/json"),), OBJECT_A, identity="Bearer TOKEN-A"),
    MockRoute("GET", "app.test", "/api/users/2", 200,
              (("Content-Type", "application/json"),), OBJECT_B, identity="Bearer TOKEN-B"),
    # 对象 3 对两个身份都放行：B 也能读到 A 的东西 —— 这是给界面点的"确认"用例
    MockRoute("GET", "app.test", "/api/users/3", 200,
              (("Content-Type", "application/json"),), OBJECT_A),
    MockRoute("GET", "app.test", "/.env", 200,
              (("Content-Type", "text/html"),), b"<!doctype html><html>spa shell</html>"),
]


def step(n, title):
    print("\n[%d] %s" % (n, title))


def seed(ws):
    """铺三条证据：A 身份读自己、B 身份读别人的对象、一条 L2（进审批栏）。

    --serve 模式也要有数据可点，否则打开是一张空表。三次请求都在预算内。
    """
    a = ws.probe.run(ProbeRequest(action_id="a1", url="http://app.test/api/users/1",
                                  identity="A", label="idor:owner"))
    b = ws.probe.run(ProbeRequest(action_id="a2", url="http://app.test/api/users/2",
                                  identity="B", label="idor:other"))
    l2 = ws.probe.run(ProbeRequest(action_id="a3", url="http://app.test/api/users/1?url=x",
                                   identity="A", label="ssrf", param_path="query:url",
                                   payload_class="oob_url"))
    return a, b, l2


def get(port, path):
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=10) as r:
        return r.status, r.headers, r.read()


def post(port, path, payload):
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path),
        data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def build() -> tuple:
    tmp = tempfile.mkdtemp(prefix="pta-ui-")
    scope = Scope(engagement_id="ENG-UI", domains=("app.test",), allow_private=True,
                  rate_per_host=1000.0, max_requests=200)
    init_workspace(tmp, scope)
    tx = MockTransport(ROUTES)
    ws = open_workspace(tmp, transport=tx, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
    ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
    ws.vault.put("cred/B/authorization", "Bearer TOKEN-B")
    return tmp, ws


def run_script(port, ws):
    ok = True

    step(1, "静态页面")
    status, headers, body = get(port, "/")
    html = body.decode("utf-8")
    print("  GET /            %d  %s  %d 字节" % (status, headers["Content-Type"], len(body)))
    print("  含四个面板: 假设队列=%s 资产图=%s 审批栏=%s 证据对比=%s" % (
        "假设队列" in html, "资产图" in html, "审批栏" in html, "证据对比" in html))
    for name in ("/ui/app.js", "/ui/style.css"):
        st, hd, bd = get(port, name)
        print("  GET %-14s %d  %-42s %6d 字节" % (name, st, hd["Content-Type"], len(bd)))
        ok = ok and st == 200

    step(2, "造证据：两条正常读 + 一条 L2（会进审批栏）")
    a, b, l2 = seed(ws)
    print("  证据 A=%s  B=%s  L2=%s" % (a.evidence_id[:12], b.evidence_id[:12], l2.status))
    ok = ok and l2.status == "pending_approval"

    step(3, "GET /api/state —— 界面一次拉全")
    _, _, body = get(port, "/api/state")
    s = json.loads(body.decode("utf-8"))
    print("  engagement=%s 请求 %d/%d 熔断=%s" % (
        s["engagement"], s["budget"]["used"], s["budget"]["max"], s["breaker"]))
    print("  模板 %d 个（含 sqli-time-blind=%s），证据 %d 条，findings %d 条" % (
        len(s["templates"]),
        any(t["id"] == "sqli-time-blind" for t in s["templates"]),
        s["evidence_count"], len(s["findings"])))
    print("  tally=%s" % json.dumps(s["tally"], ensure_ascii=False))
    for p in s["pending_approvals"]:
        print("  待审批 %s  %s  %s  %s/%s" % (
            p["fp"][:10], p["level"], p["host"], p["param_path"], p["payload_class"]))
    ok = ok and s["pending_approvals"] and s["pending_approvals"][0]["param_path"] == "query:url"

    step(4, "审批：同意此类（class，24h 内同类不再问）")
    fp = s["pending_approvals"][0]["fp"]
    out = post(port, "/api/approvals/%s/decide" % fp,
               {"decision": "approve", "scope": "class", "note": "演示放行"})
    print("  decide -> %s" % json.dumps(out, ensure_ascii=False))
    after = json.loads(get(port, "/api/state")[2].decode("utf-8"))
    print("  审批栏剩余 %d 条" % len(after["pending_approvals"]))
    ok = ok and len(after["pending_approvals"]) == 0

    step(5, "证据详情（抽屉）")
    d = json.loads(get(port, "/api/evidence/%s" % b.evidence_id)[2].decode("utf-8"))
    print("  %s %s%s  status=%d  %d 字节  %d 次采样" % (
        d["method"], d["host"], d["raw_path"], d["status"], d["body_len"], len(d["timings"])))
    print("  timings=%s" % [round(t, 2) for t in d["timings"]])
    print("  body 预览: %s" % d["body_preview"][:80])
    ok = ok and d["body_preview"].startswith("{") and d["request"]["method"] == "GET"

    step(6, "证据对比（A/B 槽）")
    diff = json.loads(get(port, "/api/evidence/%s/diff/%s"
                          % (a.evidence_id, b.evidence_id))[2].decode("utf-8"))
    print("  status %d -> %d   body 相同=%s   相似度=%.3f" % (
        diff["a"]["status"], diff["b"]["status"], diff["body_same"], diff["similarity"]))
    print("  role: user -> admin（预览里能直接看出来）")
    ok = ok and not diff["body_same"] and diff["similarity"] > 0.8

    step(7, "异步跑模板：POST /api/run，结论走 SSE（这里应是命中）")
    q = ws.bus.subscribe()
    t0 = time.time()
    out = post(port, "/api/run", {"template": "idor-object-ref",
                                  "url": "http://app.test/api/users/3",
                                  "identity_baseline": "A", "identity_probe": "B"})
    print("  202 -> run_id=%s state=%s" % (out["run_id"], out["state"]))
    events = []
    deadline = time.time() + 15
    done = None
    while time.time() < deadline:
        ev = q.get(timeout=15)
        events.append(ev["type"])
        if ev["type"] in ("run_finished", "run_failed"):
            done = ev
            print("  事件链路: %s" % " → ".join(events))
            print("  %s  status=%s  confidence=%s  用时 %.2fs" % (
                ev["type"], ev.get("status"), ev.get("confidence"), time.time() - t0))
            break
    ok = ok and done is not None and done.get("status") == "confirmed"

    step(8, "审计日志")
    logs = json.loads(get(port, "/api/logs?limit=5")[2].decode("utf-8"))
    for row in logs[-5:]:
        print("  %s  %-10s %-16s %s" % (row["ts"], row["decision"], row["tool"],
                                        (row["reason"] or "")[:48]))
    ok = ok and any(r["decision"] == "pending_approval" for r in logs)

    return ok


def main() -> int:
    tmp, ws = build()
    serve_mode = "--serve" in sys.argv
    if serve_mode:
        a, b, _ = seed(ws)
        print("已铺演示数据：证据 2 条可读（A=%s / B=%s）+ 1 条 L2 待审批"
              % (a.evidence_id[:8], b.evidence_id[:8]))
    httpd, _ = make_server(ws, bus=ws.bus, port=8765 if serve_mode else 0)
    port = httpd.server_port
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("工作区: %s" % tmp)
    print("操作台: http://127.0.0.1:%d/" % port)

    if serve_mode:
        print("\n浏览器打开上面的地址；Ctrl+C 结束。")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n收工。")
        return 0

    try:
        ok = run_script(port, ws)
    finally:
        httpd.shutdown()

    print("\n结果: %s" % ("OK（四个面板要的字段全在；审批、对比、异步执行都走通）"
                          if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
