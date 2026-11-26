"""断点续跑：账在 `action_log`，状态在 `ptt_node`，都不在内存里。

三件事必须成立，否则"续跑"只是换了个说法的重跑：

1. 重开工作区，预算从账本接上——不是从 0 起。预算是对外承诺，重启不是理由；
2. `resume=True` 时已有结论的候选一个包都不发（**跳过 ≠ 重跑**，
   否则续跑既浪费额度又制造重复副作用）；
3. `running` 与 `done:pending_approval` 都不算完成：前者是进程被杀，
   后者是"等你批"——批完还要接着跑，把它当完成等于把候选永久丢弃。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta.budget import Budget  # noqa: E402
from pta.planner import Candidate, EngagementRunner, Plan, _node_id  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockTransport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-RS"


class FixedPlanner:
    """每轮都给同一批候选（续跑要的是"同一批"，不是"新一批"）。"""

    def __init__(self, candidates):
        self.candidates = list(candidates)
        self.calls = 0

    def plan(self):
        self.calls += 1
        return Plan(candidates=list(self.candidates), notes="")


def cand(template, url, param=None):
    return Candidate(template_id=template, url=url, param_path=param, priority=0.5)


def key_of(c):
    return "%s|%s|%s" % (c.template_id, c.url, c.param_path or "")


class BudgetRestoreTest(unittest.TestCase):
    def test_restore_only_grows(self):
        b = Budget(max_requests=100)
        b.take("a.test")
        b.take("a.test")
        b.take("b.test")
        b.restore(2, {"a.test": 2})
        self.assertEqual(b.used, 3)          # 账本比内存少时不动
        b.restore(9, {"a.test": 7, "b.test": 2})
        self.assertEqual(b.used, 9)
        self.assertEqual(b.per_host.get("a.test"), 7)
        self.assertEqual(b.per_host.get("b.test"), 2)

    def test_restore_keeps_limit(self):
        b = Budget(max_requests=5)
        b.restore(9)
        self.assertEqual(b.used, 9)
        self.assertEqual(b.snapshot()["used"], 9)   # 超了就超了，不偷偷截断
        self.assertEqual(b.snapshot()["max"], 5)


class WorkspaceRestore(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-resume-")
        self.t1 = MockTransport([])
        init_workspace(self.root, Scope(engagement_id=ENG,
                                        domains=("a.test", "b.test"),
                                        allow_private=True, rate_per_host=200,
                                        max_requests=200))
        self.ws1 = open_workspace(self.root, transport=self.t1,
                                  dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        self.cands = [cand("info-disclosure-artifact", "http://a.test/one"),
                      cand("info-disclosure-artifact", "http://b.test/two")]

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def first_run(self, candidates=None):
        c = candidates if candidates is not None else self.cands
        return EngagementRunner(self.ws1, FixedPlanner(c), max_rounds=1, workers=2).run()

    # ---------- 账本 ----------
    def test_budget_is_restored_from_ledger(self):
        out = self.first_run()
        spent = self.ws1.budget.used
        self.assertGreater(spent, 0)
        self.assertEqual(out["budget"]["used"], spent)

        # 换一个 transport 重开工作区：等于"进程重启"
        t2 = MockTransport([])
        ws2 = open_workspace(self.root, transport=t2,
                             dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        self.assertEqual(ws2.budget.used, spent)
        self.assertEqual(t2.sent, [])       # 恢复预算不发包

    # ---------- 跳过 ----------
    def test_resume_does_not_resend_finished(self):
        self.first_run()
        spent = self.ws1.budget.used

        t2 = MockTransport([])
        ws2 = open_workspace(self.root, transport=t2,
                             dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        out = EngagementRunner(ws2, FixedPlanner(self.cands), max_rounds=1,
                               workers=2, resume=True).run()

        self.assertEqual(t2.sent, [])                    # 一个包都没发
        self.assertEqual(len(out["resume"]["skipped"]), 2)
        self.assertEqual(out["resume"]["start_round"], 1)
        self.assertEqual(out["resume"]["prior"]["candidates"], 2)
        self.assertGreater(out["resume"]["prior"]["requests"], 0)
        self.assertEqual(ws2.budget.used, spent)          # 额度也没再动
        self.assertEqual(out["counts"], {})               # 这一轮没有新结论

    def test_resume_keeps_previous_nodes(self):
        out1 = self.first_run()
        self.assertTrue(out1["findings"])
        before = {n["node_id"]: n["status"] for n in self.ws1.store.nodes(ENG)}

        t2 = MockTransport([])
        ws2 = open_workspace(self.root, transport=t2,
                             dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        EngagementRunner(ws2, FixedPlanner(self.cands), max_rounds=1,
                         workers=2, resume=True).run()

        after = {n["node_id"]: n["status"] for n in ws2.store.nodes(ENG)}
        for nid, status in before.items():
            if status.startswith("done:") and status != "done:pending_approval":
                self.assertEqual(after.get(nid), status)   # 结论没被覆盖成 skipped
            self.assertNotIn("skipped:resumed", [after.get(nid)])

    # ---------- 没跑完的不许跳过 ----------
    def test_running_is_not_done(self):
        c = self.cands[0]
        nid = _node_id("candidate", key_of(c))
        self.ws1.store.put_node(ENG, nid, None, "candidate", "x", "running", {})

        t2 = MockTransport([])
        ws2 = open_workspace(self.root, transport=t2,
                             dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        out = EngagementRunner(ws2, FixedPlanner([c]), max_rounds=1,
                               workers=1, resume=True).run()

        self.assertEqual(len(out["resume"]["skipped"]), 0)
        self.assertGreater(len(t2.sent), 0)              # 重新发了
        row = [n for n in ws2.store.nodes(ENG) if n["node_id"] == nid][0]
        self.assertTrue(row["status"].startswith("done:"))

    def test_pending_approval_is_not_done(self):
        c = self.cands[0]
        nid = _node_id("candidate", key_of(c))
        self.ws1.store.put_node(ENG, nid, None, "candidate", "x",
                                "done:pending_approval", {"requests": 0})

        t2 = MockTransport([])
        ws2 = open_workspace(self.root, transport=t2,
                             dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        out = EngagementRunner(ws2, FixedPlanner([c]), max_rounds=1,
                               workers=1, resume=True).run()

        self.assertEqual(len(out["resume"]["skipped"]), 0)
        self.assertGreater(len(t2.sent), 0)

    # ---------- 轮次 ----------
    def test_start_round_continues_numbering(self):
        EngagementRunner(self.ws1, FixedPlanner(self.cands), max_rounds=2,
                         workers=2).run()
        t2 = MockTransport([])
        ws2 = open_workspace(self.root, transport=t2,
                             dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        out = EngagementRunner(ws2, FixedPlanner([]), max_rounds=1,
                               workers=1, resume=True).run()
        # 上一轮跑了两轮，续跑从第 3 轮（index 2）开始
        self.assertEqual(out["resume"]["start_round"], 2)
        self.assertEqual(out["rounds"][0]["round"], 2)


if __name__ == "__main__":
    unittest.main()
