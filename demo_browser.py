"""P1.7 浏览器链路演示：xss-reflected 靠"脚本真的执行了"判定。

真 Chromium 在 DSH Windows 沙箱里起不来（命名管道被拒），所以这里用协议级假 CDP
服务器（tests/fake_cdp.py）驱动同一条代码路径：websocket 帧 → JSON-RPC → Fetch 拦截
→ DOM 快照 → oracle。

python demo_browser.py
"""
from __future__ import annotations

import copy
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
sys.path.insert(0, os.path.join(HERE, "tests"))

from pta import cdp, vhx  # noqa: E402
from pta.browser import BrowserTool  # noqa: E402
from pta.errors import VhxInvalid  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

from fake_cdp import FakeCdpServer, FakePage  # noqa: E402

PUBLIC_IP = "93.184.216.34"
URL = "http://app.test/search?q=hello"


def xss_template():
    raw = [t for t in vhx.TEMPLATES if t["id"] == "xss-reflected"][0]
    return vhx.load(copy.deepcopy(raw))


def run_case(name: str, page: FakePage, expect: str) -> dict:
    tmp = tempfile.mkdtemp(prefix="pta-demo-")
    try:
        scope = Scope(engagement_id="ENG-DEMO", domains=("app.test",), allow_private=True,
                      rate_per_host=1000.0, max_requests=200)
        init_workspace(tmp, scope)
        ws = open_workspace(tmp, transport=None, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        server = FakeCdpServer(page).start()
        wsock = cdp.WebSocket("127.0.0.1", server.port, server.path, timeout=10)
        try:
            session = cdp.CdpSession(wsock)
            tool = BrowserTool(scope=ws.scope, store=ws.store, cas=ws.cas, budget=ws.budget,
                               page_session=session, page_id="S1", target_id="T1",
                               product="FakeCdp/1.0",
                               dns=DnsPin(resolver=lambda h: [PUBLIC_IP]), bus=ws.bus)
            ex = Executor(ws.probe, ws.store, ws.scope.engagement_id, browser=tool)
            f = ex.run(xss_template(), Target(url=URL, param_path="query:q"))
        finally:
            wsock.close()
            server.close()
        ok = f.status == expect
        return {"name": name, "status": f.status, "expect": expect, "ok": ok,
                "confidence": round(f.confidence, 3), "requests": f.requests_used,
                "rationale": f.verdict.get("rationale", ""),
                "metrics": f.verdict.get("metrics", {})}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_no_browser() -> dict:
    tmp = tempfile.mkdtemp(prefix="pta-demo-")
    try:
        scope = Scope(engagement_id="ENG-DEMO", domains=("app.test",), allow_private=True,
                      rate_per_host=1000.0, max_requests=50)
        init_workspace(tmp, scope)
        ws = open_workspace(tmp, transport=None, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ex = Executor(ws.probe, ws.store, ws.scope.engagement_id, browser=None)
        try:
            ex.run(xss_template(), Target(url=URL, param_path="query:q"))
            return {"name": "no-browser", "blocked": False}
        except VhxInvalid as exc:
            return {"name": "no-browser", "blocked": True, "reason": str(exc)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    print("模板：xss-reflected（L1，oracle=dom_marker_present，动作=browser_nav）")
    print("目标：%s\n" % URL)

    cases = [
        run_case("vuln：反射并执行", FakePage(mode="vuln"), "confirmed"),
        run_case("reflect：反射但被 CSP 拦住", FakePage(mode="reflect"), "refuted"),
        run_case("safe：输出做了 HTML 编码", FakePage(mode="safe"), "refuted"),
    ]

    print("%-28s %-10s %-10s %-6s %-5s %-6s" % ("用例", "结论", "期望", "一致", "置信", "请求"))
    print("-" * 78)
    all_ok = True
    for c in cases:
        all_ok = all_ok and c["ok"]
        print("%-28s %-10s %-10s %-6s %-5.3f %-6d" % (
            c["name"], c["status"], c["expect"], "OK" if c["ok"] else "FAIL",
            c["confidence"], c["requests"]))
    print()
    for c in cases:
        m = c["metrics"]
        print("  %s → %s" % (c["name"], c["rationale"]))
        if m:
            print("    window_name_match=%s body_attr=%s reflected_only=%s" % (
                m.get("window_name_match"), m.get("body_attr"), m.get("reflected_only")))

    nb = run_no_browser()
    print()
    print("无浏览器时：%s" % ("按设计拒绝执行 → %s" % nb.get("reason") if nb["blocked"] else "竟然跑了（BUG）"))
    all_ok = all_ok and nb["blocked"]

    # 范围拦截：页面去拉站外脚本，必须在 Fetch 层被拦下并留痕
    tmp = tempfile.mkdtemp(prefix="pta-demo-")
    try:
        scope = Scope(engagement_id="ENG-DEMO", domains=("app.test",), allow_private=True,
                      rate_per_host=1000.0, max_requests=50)
        init_workspace(tmp, scope)
        ws = open_workspace(tmp, transport=None, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        server = FakeCdpServer(FakePage(mode="redirect",
                                        foreign_url="https://evil.test/steal.js")).start()
        wsock = cdp.WebSocket("127.0.0.1", server.port, server.path, timeout=10)
        try:
            session = cdp.CdpSession(wsock)
            tool = BrowserTool(scope=ws.scope, store=ws.store, cas=ws.cas, budget=ws.budget,
                               page_session=session, page_id="S1", target_id="T1",
                               product="FakeCdp/1.0",
                               dns=DnsPin(resolver=lambda h: [PUBLIC_IP]), bus=ws.bus)
            nav = tool.navigate(__import__("pta.browser", fromlist=["NavRequest"]).NavRequest(
                url=URL, label="run/xss/scope", settle_s=0.3))
        finally:
            wsock.close()
            server.close()
        denied = [r for r in ws.store.logs(scope.engagement_id) if r["decision"] == "denied"]
        print("站外子请求：%s；denied 日志 %d 条" % (nav.denied_urls or "无", len(denied)))
        if denied:
            print("  记录：%s ← %s" % (denied[0]["tool"], denied[0]["reason"]))
        all_ok = all_ok and bool(nav.denied_urls) and bool(denied)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("结果：OK（执行→确认、反射→否定、编码→否定、无浏览器→拒绝、站外→拦截）"
          if all_ok else "结果：FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
