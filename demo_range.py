"""真靶场跑分：同一批模板打在"有洞"和"没洞"两份接口上，算检出率与误报率。

跑法：python demo_range.py [--repeat 1]

和 mock 演示的区别：这里没有假传输。靶场是真 HTTP + 真 sqlite + 真 SSRF 转发，
判定链（probe → 证据 → oracle → critic）跑在真实 socket 与时序上。
一次 case 的 `confirmed` 只可能来自目标自己的行为，不可能来自我替它编的响应。

指标：
  TP  有洞接口被判 confirmed
  FN  有洞接口没判出来
  FP  没洞接口被判 confirmed（误报率 = FP / 无洞用例数）
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
sys.path.insert(0, HERE)

from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import Scope  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

import range_target  # noqa: E402

ENG = "ENG-RANGE"


def _case(name, template_id, url, *, param=None, method="GET", body=None,
          base="A", probe="A", expect="confirmed", args=None, note="", id_plus_one=None):
    return dict(name=name, template_id=template_id, url=url, param=param, method=method,
                body=body, base=base, probe=probe, expect=expect, args=args or {},
                note=note, id_plus_one=id_plus_one)


def build_cases(base: str):
    return [
        _case("sqli-error  有洞", "sqli-error-boolean", base + "/api/items?id=1",
              param="query:id", note="单引号断句 → 真 sqlite 语法错误页"),
        _case("sqli-error  无洞", "sqli-error-boolean", base + "/api/items_safe?id=1",
              param="query:id", expect="refuted", note="参数化查询"),
        _case("sqli-bool   有洞", "sqli-boolean-blind", base + "/api/items?id=1",
              param="query:id", note="1=1 有行 / 1=2 空集"),
        _case("sqli-bool   无洞", "sqli-boolean-blind", base + "/api/items_safe?id=1",
              param="query:id", expect="refuted"),
        _case("sqli-time   有洞", "sqli-time-blind", base + "/api/items?id=1",
              param="query:id", note="SLEEP(2) 在服务端真执行"),
        _case("sqli-time   无洞", "sqli-time-blind", base + "/api/items_safe?id=1",
              param="query:id", expect="refuted"),
        _case("idor        有洞", "idor-object-ref", base + "/api/users?id=1",
              param="query:id", base="A", probe="B", id_plus_one="1",
              note="B 读 A 的对象（id 不变，只换身份）；目标不看属主"),
        _case("idor        无洞", "idor-object-ref", base + "/api/users_safe?id=1",
              param="query:id", base="A", probe="B", id_plus_one="1", expect="refuted"),
        _case("ssrf        有洞", "ssrf-internal-service", base + "/api/fetch?url=x",
              param="query:url", note="转发到内网 127.0.0.1:2375"),
        _case("ssrf        无洞", "ssrf-internal-service", base + "/api/fetch_safe?url=x",
              param="query:url", expect="refuted", note="域名白名单"),
        _case("mass-assign 有洞", "mass-assignment-privilege", base + "/api/profile",
              method="POST", param="body:*", body={"name": "widget"}, note="role 被一起吞下"),
        _case("mass-assign 无洞", "mass-assignment-privilege", base + "/api/profile_safe",
              method="POST", param="body:*", body={"name": "widget"}, expect="refuted",
              note="只接受 name"),
    ]


def run(ws, c, approvals):
    from pta import overrides as ov

    if c["template_id"] in approvals:
        for pp, pc in approvals[c["template_id"]]:
            ws.gate.decide(ENG, "http_probe", "127.0.0.1", pp, pc, "L2", "approve",
                           scope="class")
    tpl, _frag = ov.load_template(ws, c["template_id"])
    target = Target(url=c["url"], param_path=c["param"], method=c["method"],
                    body_json=c["body"], identity_baseline=c["base"],
                    identity_probe=c["probe"],
                    id_plus_one=(None if c["id_plus_one"] is None
                                 else str(c["id_plus_one"])))
    t0 = time.perf_counter()
    finding = Executor(ws.probe, ws.store, ENG).run(tpl, target)
    took = time.perf_counter() - t0
    crit = Critic(ws).review_finding(finding, apply=False)
    return finding, crit, took


def main() -> int:
    httpd, docker, port = range_target.start(0, 2375)
    base = "http://127.0.0.1:%d" % port
    root = os.path.join(tempfile.mkdtemp(prefix="pta-range-"), "eng")
    init_workspace(root, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                               allow_private=True, allowed_ports=(port,),
                               max_requests=600, rate_per_host=1000.0))
    ws = open_workspace(root)
    # 身份从 vault 取：靶场用 Bearer token 区分 A/B，这里把两套凭据装进工作区
    ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
    ws.vault.put("cred/B/authorization", "Bearer TOKEN-B")
    approvals = {
        "sqli-time-blind": [("query:id", "delay_short")],
        "mass-assignment-privilege": [("body:*", "extra_field")],
        "ssrf-internal-service": [("query:url", "internal_metadata_url"),
                                  ("query:url", "internal_docker_url"),
                                  ("query:url", "internal_etcd_url")],
    }
    rows = []
    print("靶场：%s   内网 docker：%s\n"
          % (base, ("up（127.0.0.1:%d）" % range_target.Handler.internal_port)
             if docker else "未起（SSRF 用例会判否）"))
    try:
        for c in build_cases(base):
            f, crit, took = run(ws, c, approvals)
            ok = (f.status == c["expect"])
            rows.append((c, f, crit, took, ok))
            print("%-18s %-11s %.3f  %5.1fs  critic=%-6s %s"
                  % (c["name"], f.status, f.confidence, took, crit.status,
                     "OK" if ok else "MISS(期望 %s)" % c["expect"]))
            print("   %s" % (f.verdict.get("rationale") or f.stop_reason or "")[:110])
            if f.stop_reason:
                print("   停止：%s（请求 %d 发）" % (f.stop_reason, f.requests_used))
            if c["note"]:
                print("   备注：%s" % c["note"])
    finally:
        httpd.shutdown()
        if docker is not None:
            docker.shutdown()
        shutil.rmtree(os.path.dirname(root), ignore_errors=True)

    vuln = [r for r in rows if r[0]["expect"] == "confirmed"]
    clean = [r for r in rows if r[0]["expect"] == "refuted"]
    tp = sum(1 for r in vuln if r[1].status == "confirmed")
    fn = len(vuln) - tp
    fp = sum(1 for r in clean if r[1].status == "confirmed")
    tn = len(clean) - fp
    print("\n检出（有洞接口）：%d/%d   漏报：%d" % (tp, len(vuln), fn))
    print("误报（无洞接口）：%d/%d   误报率：%.0f%%" % (fp, len(clean),
                                               100.0 * fp / max(len(clean), 1)))
    print("证据条数：%d   findings：%d"
          % (len(ws.store.list_evidence(ENG)) if hasattr(ws.store, "list_evidence")
             else -1, len(ws.store.list_findings(ENG))))
    ok = fn == 0 and fp == 0
    print("\n结果：%s" % ("OK（真靶场上零漏报、零误报）" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
