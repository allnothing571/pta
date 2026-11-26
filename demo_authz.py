"""P1.8 缺失授权演示：authz-missing-endpoint 判"不出示身份能不能读"。

和 IDOR 的区别：IDOR 是换个身份读别人的对象，这里是**根本不带凭据**。
两类假阳性必须被拦住：返回登录页（200）、返回 403 页面本身（200 包装）。
拒绝模板不是硬编码的登录页，而是本次任务真实取到的一次 403（control 请求）。

python demo_authz.py
"""
from __future__ import annotations

import copy
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import vhx  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockRoute, MockTransport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ORDERS = (b'{"orders":[{"id":1001,"amount":88.5,"status":"shipped"},'
          b'{"id":1002,"amount":12.0,"status":"open"}],"user":"alice"}')
DENY403 = b'{"error":"forbidden","message":"admin role required"}'
LOGIN = (b'<!doctype html><html><head><title>Sign in</title></head><body>'
         b'<form action="/login" method="post"><input name="username">'
         b'<input name="password"><button>Log in</button></form></body></html>')

CASES = [
    ("vuln：无凭据照样返回订单", 200, ORDERS, True,
     "confirmed", "接口缺失授权"),
    ("login-page：200 但返回登录页", 200, LOGIN, True,
     "refuted", "长得不像数据，判否"),
    ("deny-page：200 但内容就是 403 页", 200, DENY403, True,
     "refuted", "与拒绝模板等价，判否"),
    ("401：直接拒绝", 401, DENY403, True,
     "refuted", "要认证"),
    ("redirect：302 跳登录", 302, b"", True,
     "refuted", "跳转即拒绝"),
]


def authz_template():
    return vhx.load(copy.deepcopy(
        [t for t in vhx.TEMPLATES if t["id"] == "authz-missing-endpoint"][0]))


def run_case(name, status, body, with_control, expect_status, note):
    tmp = tempfile.mkdtemp(prefix="pta-authz-")
    try:
        scope = Scope(engagement_id="ENG-AUTHZ", domains=("app.test",), allow_private=True,
                      rate_per_host=1000.0, max_requests=200)
        init_workspace(tmp, scope)
        routes = [
            MockRoute("GET", "app.test", "/api/orders", 200,
                      (("Content-Type", "application/json"),), ORDERS,
                      identity="Bearer TOKEN-A"),
            MockRoute("GET", "app.test", "/api/orders", status,
                      (("Content-Type", "application/json"),), body, identity=""),
            MockRoute("GET", "app.test", "/admin/audit", 403,
                      (("Content-Type", "application/json"),), DENY403, identity=""),
        ]
        ws = open_workspace(tmp, transport=MockTransport(routes),
                            dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
        target = Target(url="http://app.test/api/orders", identity_baseline="A",
                        identity_probe="none",
                        control_url="http://app.test/admin/audit" if with_control else None)
        finding = Executor(ws.probe, ws.store, "ENG-AUTHZ").run(authz_template(), target)
        crit = Critic(ws).review_finding(finding)
        ok = finding.status == expect_status
        return {"name": name, "status": finding.status, "conf": finding.confidence,
                "requests": finding.requests_used, "evidence": len(finding.evidence_ids),
                "critic": crit.status, "note": note, "ok": ok,
                "rationale": finding.verdict.get("rationale", "")}
    finally:
        shutil.rmtree(tmp, True)


def main():
    print("模板：authz-missing-endpoint（L1，CWE-862）")
    print("判定：probe 与授权视角等价 → confirmed；先排除拒绝模板与跳转")
    print("")
    header = "场景".ljust(30) + "结论".ljust(12) + "置信度".ljust(9) + \
             "请求".ljust(6) + "证据".ljust(6) + "Critic".ljust(9) + "说明"
    print(header)
    print("-" * 108)
    all_ok = True
    for name, status, body, with_control, expect, note in CASES:
        r = run_case(name, status, body, with_control, expect, note)
        all_ok = all_ok and r["ok"]
        print(name.ljust(30) + r["status"].ljust(12) +
              ("%.3f" % r["conf"]).ljust(9) + str(r["requests"]).ljust(6) +
              str(r["evidence"]).ljust(6) + r["critic"].ljust(9) + r["note"])
    print("")
    # 额外一条：不给控制接口时，置信度降到 0.88（少一层反证）
    r = run_case("no-control：没有拒绝模板", 200, ORDERS, False, "confirmed", "反证少一层")
    all_ok = all_ok and r["ok"]
    print("no-control：不给兄弟接口 → %s %.3f（证据 %d 条，无拒绝模板）"
          % (r["status"], r["conf"], r["evidence"]))
    print("")
    print("理由示例：%s" % run_case(*CASES[0])["rationale"])
    print("")
    print("结果：%s" % ("OK（缺失授权确认、登录页/403页/401/跳转全部判否）" if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
