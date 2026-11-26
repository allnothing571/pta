"""Runner 并发 + PTT 任务树。

三条边界都要测到：并发有上限、预算不越界、审批暂停后不再派活。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta.budget import Budget  # noqa: E402
from pta.errors import BudgetExceeded  # noqa: E402
from pta.planner import Candidate, EngagementRunner, Plan  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockTransport, RawResponse  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-R"


class SlowTransport(MockTransport):
    """每个请求睡一会儿，用来观察真实并发度。"""

    def __init__(self, delay_ms=60, status=200, body=b'{"ok":true}'):
        super().__init__([])
        self.delay_s = delay_ms / 1000.0
        self.status = status
        self.body = body
        self.lock = threading.Lock()
        self.inflight = 0
        self.max_inflight = 0

    def send(self, req, timeout_s=10.0):
        with self.lock:
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
        self.sent.append(req)
        time.sleep(self.delay_s)
        with self.lock:
            self.inflight -= 1
        t0 = time.perf_counter()
        return RawResponse(status=self.status, reason="OK", http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),), body=self.body,
                           t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


class StubPlanner:
    def __init__(self, candidates):
        self.candidates = candidates
        self.calls = 0

    def plan(self):
        self.calls += 1
        if self.calls > 1:
            return Plan(candidates=[], notes="no_more")
        return Plan(candidates=list(self.candidates), notes="")


def cand(template, url, param=None, priority=0.5):
    return Candidate(template_id=template, url=url, param_path=param, priority=priority)


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-run-")
        self.transport = SlowTransport()
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("a.test", "b.test", "c.test"),
                                        allow_private=True, rate_per_host=200,
                                        max_requests=200))
        self.ws = open_workspace(self.root, transport=self.transport,
                                 dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def runner(self, candidates, workers=3, max_rounds=1):
        return EngagementRunner(self.ws, StubPlanner(candidates), max_rounds=max_rounds,
                                workers=workers)


class ConcurrencyTest(WorkspaceTest):
    def test_parallel_is_bounded_by_workers(self):
        cands = [cand("info-disclosure-artifact", "http://%s.test/one" % h)
                 for h in ("a", "b", "c", "a", "b", "c")]
        r = self.runner(cands, workers=3)
        out = r.run()
        self.assertEqual(out["workers"], 3)
        self.assertGreaterEqual(self.transport.max_inflight, 2)
        self.assertLessEqual(self.transport.max_inflight, 3)
        self.assertEqual(out["counts"].get("refuted", 0) + out["counts"].get("confirmed", 0), 6)

    def test_workers_one_is_serial(self):
        cands = [cand("info-disclosure-artifact", "http://a.test/%d" % i) for i in range(4)]
        r = self.runner(cands, workers=1)
        r.run()
        self.assertEqual(self.transport.max_inflight, 1)

    def test_results_keep_plan_order(self):
        cands = [cand("info-disclosure-artifact", "http://%s.test/%d" % (h, i))
                 for i, h in enumerate(("c", "b", "a", "c", "b"))]
        r = self.runner(cands, workers=3)
        r.run()
        # 顺序按提交顺序回填：findings[i] 对应 candidates[i]，和谁先跑完无关
        self.assertEqual([c.url for c in cands],
                         [f.verdict.get("target_url", c.url) for f, c in
                          zip(r.rounds[0].findings, cands)])


class BudgetTest(WorkspaceTest):
    def test_budget_never_exceeded(self):
        self.ws.budget.max_requests = 4
        cands = [cand("info-disclosure-artifact", "http://a.test/%d" % i) for i in range(9)]
        out = self.runner(cands, workers=3).run()
        self.assertEqual(out["budget"]["used"], 4)
        self.assertEqual(out["stop_reason"], "budget_exhausted")
        self.assertLessEqual(len(self.transport.sent), 4)

    def test_counter_is_atomic_across_threads(self):
        b = Budget(max_requests=50, rate_per_host=10000)
        ok = []
        err = []

        def worker():
            for _ in range(10):
                try:
                    b.take("h")
                    ok.append(1)
                except BudgetExceeded:
                    err.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(ok), 50)
        self.assertEqual(len(err), 30)
        self.assertEqual(b.used, 50)


class PttTest(WorkspaceTest):
    def test_tree_has_round_asset_candidate(self):
        cands = [cand("info-disclosure-artifact", "http://a.test/1"),
                 cand("info-disclosure-artifact", "http://b.test/1")]
        out = self.runner(cands, workers=2).run()
        self.assertEqual(out["ptt"]["by_kind"].get("round"), 1)
        self.assertEqual(out["ptt"]["by_kind"].get("asset"), 2)
        self.assertEqual(out["ptt"]["by_kind"].get("candidate"), 2)
        rows = self.ws.store.nodes(ENG)
        cands_rows = [r for r in rows if r["kind"] == "candidate"]
        self.assertTrue(all(r["status"].startswith("done:") for r in cands_rows))
        self.assertTrue(all(r["parent_id"] for r in cands_rows))

    def test_round_node_records_stop(self):
        self.ws.budget.max_requests = 1
        cands = [cand("info-disclosure-artifact", "http://a.test/%d" % i) for i in range(3)]
        out = self.runner(cands, workers=1).run()
        rounds = [r for r in self.ws.store.nodes(ENG) if r["kind"] == "round"]
        self.assertEqual(len(rounds), 1)
        self.assertIn("budget_exhausted", rounds[0]["status"] + out["stop_reason"])

    def test_rerun_updates_same_node(self):
        cands = [cand("info-disclosure-artifact", "http://a.test/1")]
        self.runner(cands).run()
        first = len(self.ws.store.nodes(ENG))
        self.runner(cands).run()
        second = len(self.ws.store.nodes(ENG))
        self.assertEqual(first, second, "同一轮同一候选应当复用节点，不是每次新增")


class PauseTest(WorkspaceTest):
    def test_pending_approval_stops_later_batches(self):
        # 第一条是 L2 且没审批 → 暂停；后面两条不该被派发
        cands = [cand("ssrf-internal-service", "http://a.test/fetch", "query:url", 0.9),
                 cand("info-disclosure-artifact", "http://a.test/x"),
                 cand("info-disclosure-artifact", "http://a.test/y")]
        out = self.runner(cands, workers=1).run()
        self.assertTrue(out["stop_reason"].startswith("pending_approval"), out["stop_reason"])
        self.assertEqual(len(self.transport.sent), 1)
        rows = [r for r in self.ws.store.nodes(ENG) if r["kind"] == "candidate"]
        self.assertEqual(len(rows), 1, "暂停后不该再为后续候选建节点")
        self.assertTrue(rows[0]["status"].endswith("pending_approval"), rows[0]["status"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
