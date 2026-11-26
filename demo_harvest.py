"""接口采集（harvest）演示：页面自己发的请求，变成 Planner 的候选。

为什么这个演示重要：在此之前，"接口有哪些参数"只能靠 `name_hint="id|q|search"`
猜。真实应用的接口是页面里的脚本写出来的——`POST /api/v2/profile
{"displayName": "...", "role": "user"}`——这句话在浏览器里真的发过一次，
只要记下来，就不用猜。

真 Chromium 在 DSH Windows 沙箱里起不来（命名管道被拒），所以这里用协议级假 CDP
服务器（tests/fake_cdp.py）驱动同一条代码路径：Network 事件 → Harvester →
harvest 证据 → PlannerState → heuristic_candidates。

python demo_harvest.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
sys.path.insert(0, os.path.join(HERE, "tests"))

from pta import cdp  # noqa: E402
from pta.browser import BrowserTool, NavRequest  # noqa: E402
from pta.harvest import Harvester  # noqa: E402
from pta.planner import PlannerState, heuristic_candidates  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

from fake_cdp import FakeCdpServer, FakePage  # noqa: E402

PUBLIC_IP = "93.184.216.34"
URL = "http://app.test/dashboard"

API_CALLS = [
    # 同一屏会重复拉同一份数据：形状相同，只该记一条
    {"url": "/api/v2/profile?tab=main", "method": "POST",
     "postData": '{"displayName": "w", "role": "user"}',
     "body": '{"id": 7, "displayName": "w", "role": "admin"}'},
    {"url": "/api/v2/profile?tab=main", "method": "POST",
     "postData": '{"displayName": "w2", "role": "user"}',
     "body": '{"id": 7, "displayName": "w2", "role": "admin"}'},
    # 参数名不同 → 形状不同 → 必须各记一条
    {"url": "/api/v2/orders?id=41&expand=items", "method": "GET",
     "body": '{"id": 41, "total": 120}'},
    {"url": "/api/v2/orders?id=42&expand=items", "method": "GET",
     "body": '{"id": 42, "total": 88}'},
    # 跨站：不在授权范围，任何情况下都不入库
    {"url": "http://analytics.other.test/collect?uid=1", "type": "Fetch", "body": "{}"},
    # 静态资源：参数在 URL 里已经拿到了，正文没意义
    {"url": "/static/app.js", "type": "Script"},
]


def scan(api_calls, harvest=True, label="harvest"):
    tmp = tempfile.mkdtemp(prefix="pta-demo-")
    try:
        scope = Scope(engagement_id="ENG-DEMO", domains=("app.test",), allow_private=True,
                      rate_per_host=1000.0, max_requests=50)
        init_workspace(tmp, scope)
        ws = open_workspace(tmp, transport=None, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        page = FakePage(mode="safe")
        page.api_calls = list(api_calls)
        server = FakeCdpServer(page).start()
        wsock = cdp.WebSocket("127.0.0.1", server.port, server.path, timeout=10)
        try:
            session = cdp.CdpSession(wsock)
            tool = BrowserTool(scope=ws.scope, store=ws.store, cas=ws.cas, budget=ws.budget,
                               page_session=session, page_id="S1", target_id="T1",
                               product="FakeCdp/1.0",
                               dns=DnsPin(resolver=lambda h: [PUBLIC_IP]), bus=ws.bus)
            res = tool.navigate(NavRequest(url=URL, label=label, settle_s=0.3,
                                          harvest=harvest, harvest_limit=12))
        finally:
            wsock.close()
            server.close()
        state = PlannerState.collect(ws)
        cands = heuristic_candidates(state)
        return {"res": res, "calls": res.harvest_calls, "assets": state.assets,
                "cands": cands}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def show_table(calls):
    print("  %-6s %-22s %-16s %-20s %-10s %-5s" % (
        "方法", "路径", "query 名", "body 字段", "类型", "状态"))
    print("  " + "-" * 84)
    for c in calls:
        print("  %-6s %-22s %-16s %-20s %-10s %-5s" % (
            c["method"], c["path"], ",".join(c["query_names"]) or "-",
            ",".join(c["body_fields"]) or "-", c["resource_type"], c["status"]))


def main() -> int:
    ok = True

    print("① 不带采集：页面照常加载，但接口一条都没留下")
    off = scan(API_CALLS, harvest=False)
    print("   harvested=%d  证据=%s" % (len(off["res"].harvested), off["res"].evidence_id[:12]))
    ok = ok and off["res"].status == "ok" and not off["res"].harvested
    print()

    print("② 打开采集：同形状的重复调用只记一条；跨站与静态资源被丢")
    on = scan(API_CALLS)
    show_table(on["calls"])
    print("   harvested=%d 条证据（6 条网络请求 → 3 条形状）" % len(on["res"].harvested))
    shapes = [(c["method"], c["path"], tuple(c["query_names"])) for c in on["calls"]]
    dup = len(shapes) != len(set(shapes))
    paths = [c["path"] for c in on["calls"]]
    ok = ok and on["res"].status == "ok" and len(on["calls"]) == 3 and not dup
    ok = ok and paths.count("/api/v2/profile") == 1 and paths.count("/api/v2/orders") == 1
    ok = ok and all(c["host"] == "app.test" for c in on["calls"])
    print()

    print("③ 同一批调用，Planner 现在能生成什么候选")
    print("  %-30s %-14s %-6s" % ("模板", "参数路径", "权重"))
    print("  " + "-" * 60)
    for c in on["cands"]:
        print("  %-30s %-14s %-6.2f" % (c.template_id, c.param_path or "-", c.priority))
    ids = {c.template_id for c in on["cands"]}
    ok = ok and "mass-assignment-privilege" in ids
    print()

    print("④ 对照：没有采集时，Planner 对同一个接口只能猜")
    no = scan([], harvest=True)
    print("  资产数=%d  候选数=%d" % (len(no["assets"]), len(no["cands"])))
    for c in no["cands"]:
        print("    %-30s %-14s %-6.2f  %s" % (c.template_id, c.param_path or "-",
                                             c.priority, c.rationale))
    ok = ok and not any(c.template_id == "mass-assignment-privilege" for c in no["cands"])
    print()

    print("⑤ Harvester 自己的账：跨站丢了几条、静态丢了几条")
    h = Harvester(allowed_hosts=("app.test",))
    h.on_event("Network.requestWillBeSent", {
        "requestId": "1", "type": "XHR",
        "request": {"url": "http://app.test/api/a?x=1", "method": "GET"}})
    h.on_event("Network.requestWillBeSent", {
        "requestId": "2", "type": "Fetch",
        "request": {"url": "http://other.test/b", "method": "GET"}})
    h.on_event("Network.requestWillBeSent", {
        "requestId": "3", "type": "Image",
        "request": {"url": "http://app.test/c.png", "method": "GET"}})
    st = h.stats()
    print("   seen=%d kept=%d skipped_type=%d skipped_cross_origin=%d" % (
        st["seen"], st["kept"], st["skipped_type"], st["skipped_cross_origin"]))
    ok = ok and st["kept"] == 1 and st["skipped_type"] == 1 and st["skipped_cross_origin"] == 1
    print()

    print("结果：%s" % ("OK（采集只记录事实，判定链一行未改）" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
