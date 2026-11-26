# -*- coding: utf-8 -*-
"""断点续跑演示：把一个任务"杀一次"，看它接着跑。

要证明三件事：

1. 预算从账本接上——不是从 0 起。重启不是把额度还给你的理由；
2. 已有结论的候选一个包都不发。**跳过是靠换 transport 验的**：续跑如果偷偷
   重发了，新 transport 的 `sent` 会立刻长出东西来，赖不掉；
3. `running`（进程被杀）和 `done:pending_approval`（等你批）都不算完成。

第一次跑用真模板真判定：`sqli-error-boolean` 打一个"带单引号就 500"的假服务器。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta.planner import Candidate, EngagementRunner, Plan, _node_id  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockTransport, RawResponse  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-DEMO-RESUME"


class QuoteTransport(MockTransport):
    """带单引号就报错——一个有洞的接口。其余请求正常。"""

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        q = "&".join("%s=%s" % (k, v) for k, v in req.query)
        path = req.raw_path + (("?" + q) if q else "")
        hit = ("'" in path) or ("%27" in path) or ('"' in path) or ("%22" in path)
        t0 = time.perf_counter()
        if hit:
            body = b'{"error":"sqlite3.OperationalError: near \\"%s\\": syntax error"}'
            status = 500
        else:
            body = b'{"items":[{"id":1,"name":"apple"}]}'
            status = 200
        return RawResponse(status=status, reason="OK" if status == 200 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),),
                           body=body, t_send=t0, t_first_byte=t0, t_end=t0)


class FixedPlanner:
    def __init__(self, candidates, notes=""):
        self.candidates = list(candidates)
        self.notes = notes
        self.calls = 0

    def plan(self):
        self.calls += 1
        return Plan(candidates=list(self.candidates), notes=self.notes)


def cand(template, url, param=None):
    return Candidate(template_id=template, url=url, param_path=param, priority=0.5)


def key_of(c):
    return "%s|%s|%s" % (c.template_id, c.url, c.param_path or "")


def line(title):
    print("")
    print("-" * 68)
    print(title)


def main():
    root = tempfile.mkdtemp(prefix="pta-demo-resume-")
    checks = []
    try:
        init_workspace(root, Scope(engagement_id=ENG, domains=("app.test",),
                                  allow_private=True, rate_per_host=200,
                                  max_requests=200))
        cands = [cand("sqli-error-boolean", "http://app.test/api/items", "query:id"),
                 cand("info-disclosure-artifact", "http://app.test/robots.txt")]

        # ---------- ① 第一次跑 ----------
        t1 = QuoteTransport([])
        ws1 = open_workspace(root, transport=t1, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        out1 = EngagementRunner(ws1, FixedPlanner(cands), max_rounds=1, workers=2).run()
        line("① 第一次跑：两个候选都跑完，结论入 PTT")
        for f in out1["findings"]:
            print("   %-26s %-12s conf=%.3f  请求 %d 发"
                  % (f["template_id"], f["status"], f["confidence"], f["requests_used"]))
        print("   本轮共发包 %d，账本 used=%d" % (len(t1.sent), ws1.budget.used))
        nodes1 = ws1.store.nodes(ENG)
        done1 = [n for n in nodes1 if n["kind"] == "candidate" and n["status"].startswith("done:")]
        print("   PTT：%d 个节点，其中 %d 个 done:*" % (len(nodes1), len(done1)))
        spent = ws1.budget.used
        checks.append(("第一次跑出了结论", len(done1) == 2 and spent > 0))
        checks.append(("至少一个判成 confirmed",
                       any(f["status"] == "confirmed" for f in out1["findings"])))

        # ---------- ② 进程被杀：重开工作区 ----------
        line("② 进程被杀：重开工作区（换一个 transport，等于新进程）")
        t2 = QuoteTransport([])
        ws2 = open_workspace(root, transport=t2, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        print("   账本里 %d 条 ok 请求 → budget.used=%d（不是从 0 起）"
              % (ws2.store.count_sent(ENG), ws2.budget.used))
        print("   按主机：%s" % (ws2.store.sent_by_host(ENG),))
        checks.append(("预算接上了", ws2.budget.used == spent))

        # ---------- ③ 续跑：同一批候选 ----------
        line("③ 续跑同一批候选：应该一个包都不发")
        out2 = EngagementRunner(ws2, FixedPlanner(cands), max_rounds=1,
                                workers=2, resume=True).run()
        res = out2["resume"]
        print("   start_round=%d 跳过 %d 个  prior=%s"
              % (res["start_round"], len(res["skipped"]), res["prior"]))
        for s in res["skipped"]:
            print("   跳过：%-26s %s" % (s["template_id"], s["url"]))
        print("   新 transport 收到的请求数：%d" % len(t2.sent))
        print("   额度变化：%d → %d" % (spent, ws2.budget.used))
        checks.append(("续跑没有发包", len(t2.sent) == 0))
        checks.append(("续跑没动额度", ws2.budget.used == spent))
        checks.append(("跳过了两个", len(res["skipped"]) == 2))
        checks.append(("轮次接着编号", res["start_round"] == 1))

        # ---------- ④ 多出一个候选 ----------
        line("④ 第二轮多出一个候选：只跑新的那个")
        extra = cand("path-traversal-lfi", "http://app.test/static", "query:file")
        out3 = EngagementRunner(ws2, FixedPlanner(cands + [extra]), max_rounds=1,
                                workers=2, resume=True).run()
        res3 = out3["resume"]
        print("   跳过 %d 个，实际发包 %d" % (len(res3["skipped"]), len(t2.sent)))
        print("   新结论：%s" % [(f["template_id"], f["status"]) for f in out3["findings"]])
        checks.append(("只跑了新候选", len(out3["findings"]) == 1
                       and out3["findings"][0]["template_id"] == "path-traversal-lfi"))

        # ---------- ⑤ pending 不算完成 ----------
        line("⑤ 等你批的候选不算完成：下一轮会重跑")
        nid = _node_id("candidate", key_of(extra))
        ws2.store.put_node(ENG, nid, None, "candidate", "x", "done:pending_approval",
                           {"requests": 0})
        before = len(t2.sent)
        out4 = EngagementRunner(ws2, FixedPlanner([extra]), max_rounds=1,
                                workers=1, resume=True).run()
        print("   跳过 %d 个，重新发包 %d 发"
              % (len(out4["resume"]["skipped"]), len(t2.sent) - before))
        checks.append(("pending 被重跑", len(out4["resume"]["skipped"]) == 0
                       and len(t2.sent) > before))

        # ---------- 汇总 ----------
        line("自检")
        bad = 0
        for name, ok in checks:
            print("   %s %s" % ("OK  " if ok else "FAIL", name))
            bad += 0 if ok else 1
        print("")
        if bad:
            print("结果：FAIL（%d 项没过）" % bad)
            return 1
        print("结果：OK（断点续跑不发重复请求，也不把没跑完的当跑完了）")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
