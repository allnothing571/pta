"""竞态（race-condition-idempotency + idempotency_violation）。

一个请求同时发 N 发，看服务端把同一操作接受了几次。
幂等：只有 1 发拿到 2xx；不幂等：多发同时通过（"查有没有做过"都在"做"之前）。
"""
from __future__ import annotations

import json
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

from pta import vhx  # noqa: E402
from pta.budget import Budget  # noqa: E402
from pta.errors import BudgetExceeded  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.oracles import Observation, ORACLE_REGISTRY  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockTransport, RawResponse  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-RACE"


def obs(statuses, role="probe", status=200, body=b'{"ok":true}'):
    return Observation(role=role, evidence_id="ev-%s" % role, identity="A", method="POST",
                       url="http://app.test/api/coupons", status=status,
                       content_type="application/json",
                       body_sha256="%064x" % 1, body_len=len(body), body=body,
                       headers={"content-type": "application/json"},
                       burst_statuses=tuple(statuses))


def verdict(obs_list, **args):
    o = ORACLE_REGISTRY["idempotency_violation"]()
    return o.run(obs_list, o.Args(**args))


class OracleTest(unittest.TestCase):
    def test_multiple_successes_confirm(self):
        v = verdict([obs([201, 201, 201, 201, 201])])
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.90)
        self.assertEqual(v.metrics["successes"], 5)

    def test_two_successes_is_enough(self):
        v = verdict([obs([201, 409, 201, 409, 409])])
        self.assertTrue(v.passed)
        self.assertEqual(v.metrics["successes"], 2)

    def test_single_success_is_idempotent(self):
        v = verdict([obs([201, 409, 409, 409, 409])])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.15)
        self.assertIn("幂等", v.rationale)

    def test_all_rejected_is_not_evidence(self):
        v = verdict([obs([400, 400, 400, 400, 400])])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.15)
        self.assertIn("请求本身可能无效", v.rationale)

    def test_all_server_errors_is_weaker(self):
        v = verdict([obs([500, 502, 500, 500, 500])])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.10)

    def test_single_request_without_burst_is_not_evidence(self):
        v = verdict([obs(())])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("probe:burst", v.missing_evidence)
        self.assertIn("单发", v.rationale)

    def test_missing_probe(self):
        v = verdict([])
        self.assertFalse(v.passed)
        self.assertEqual(v.missing_evidence, ("probe",))

    def test_min_success_is_configurable(self):
        v = verdict([obs([201, 201, 409, 409, 409])], min_success=3)
        self.assertFalse(v.passed)

    def test_statuses_show_up_in_metrics(self):
        v = verdict([obs([201, 201, 409, 409, 409])])
        self.assertEqual(v.metrics["burst"], 5)
        self.assertEqual(sorted(set(v.metrics["statuses"])), [201, 409])
        self.assertEqual(v.metrics["rejects"], 3)


class BudgetBurstTest(unittest.TestCase):
    def test_reserve_n_counts_all_at_once(self):
        b = Budget(max_requests=10, rate_per_host=1000.0)
        b.reserve_n(5, "app.test")
        self.assertEqual(b.snapshot()["used"], 5)
        self.assertEqual(b.snapshot()["per_host"]["app.test"], 5)

    def test_reserve_n_does_not_wait_per_request(self):
        # 5 发/s 限速下，逐发 take() 要等 ~0.8s；reserve_n 只等第一发的时隙。
        b = Budget(max_requests=10, rate_per_host=5.0)
        spent = {}
        for i in range(5):
            t0 = time.perf_counter()
            b.take("app.test")
            spent[i] = time.perf_counter() - t0
        serial = sum(spent.values())
        b2 = Budget(max_requests=10, rate_per_host=5.0)
        t0 = time.perf_counter()
        b2.reserve_n(5, "app.test")
        burst = time.perf_counter() - t0
        self.assertGreater(serial, burst * 2)

    def test_reserve_n_refuses_when_budget_too_small(self):
        b = Budget(max_requests=3, rate_per_host=1000.0)
        with self.assertRaises(BudgetExceeded):
            b.reserve_n(5, "app.test")
        # 失败的预约不留账
        self.assertEqual(b.snapshot()["used"], 0)


class CouponServer(MockTransport):
    """优惠券服务：mode=leaky 时 N 发都通过，mode=guarded 时只有第一发通过。"""

    def __init__(self, mode="leaky"):
        super().__init__([])
        self.mode = mode
        self._lock = threading.Lock()
        self.accepted = 0
        self.bodies = []

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        t0 = time.perf_counter()
        body = req.body or b"{}"
        self.bodies.append(body)
        with self._lock:
            if self.mode == "error":
                status, resp = 500, b'{"error":"boom"}'
            elif self.mode == "deny":
                status, resp = 403, b'{"error":"forbidden"}'
            elif self.mode == "guarded":
                if self.accepted == 0:
                    self.accepted += 1
                    status, resp = 201, b'{"ok":true}'
                else:
                    status, resp = 409, b'{"error":"already redeemed"}'
            else:  # leaky：两次"检查"都发生在"写入"之前
                self.accepted += 1
                status, resp = 201, b'{"ok":true}'
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),),
                           body=resp, t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


class ExecutorTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-race-")
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("app.test",),
                                        allow_private=True, rate_per_host=200, max_requests=200))
        self.ws = open_workspace(self.root, transport=CouponServer("leaky"),
                                 dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        self.ws.vault.put("cred/A/authorization", "Bearer A")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_case(self, mode="leaky", approve=True, burst=None):
        srv = self.ws.probe.transport
        srv.mode = mode
        srv.accepted = 0
        srv.bodies = []
        del srv.sent[:]
        if approve:
            self.ws.gate.decide(ENG, "http_probe", "app.test", "body:*", "write_marker",
                                "L2", "approve", scope="class")
        eng = Executor(self.ws.probe, self.ws.store, ENG)
        raw = [t for t in vhx.TEMPLATES if t["id"] == "race-condition-idempotency"][0]
        if burst is not None:
            raw = json.loads(json.dumps(raw))
            raw["probe"]["burst"] = burst
        tpl = vhx.load(raw)
        target = Target(url="http://app.test/api/coupons", method="POST", param_path="body:*",
                        identity_baseline="A", identity_probe="A",
                        body_json={"code": "SUMMER-2026"})
        return eng.run(tpl, target)

    def test_leaky_server_confirms(self):
        f = self.run_case("leaky")
        self.assertEqual(f.status, "confirmed", f.verdict.get("rationale"))
        self.assertGreaterEqual(f.confidence, 0.85)
        self.assertEqual(f.verdict["metrics"]["successes"], 5)
        # 1 发基线 + 5 发并发
        self.assertEqual(f.requests_used, 6)

    def test_guarded_server_refutes(self):
        f = self.run_case("guarded")
        self.assertEqual(f.status, "refuted", f.verdict.get("rationale"))
        self.assertLessEqual(f.confidence, 0.15)
        self.assertIn("幂等", f.verdict["rationale"])

    def test_unapproved_sends_nothing(self):
        f = self.run_case("leaky", approve=False)
        self.assertEqual(f.status, "pending_approval")
        # 基线（不带载荷）照发一次是正常的；不该发生的是"没批就写"
        sent = self.ws.probe.transport.sent
        self.assertEqual(len(sent), 1, [r.method for r in sent])
        self.assertEqual([r for r in sent if b"pta" in (r.body or b"")], [])

    def test_all_burst_requests_carry_the_same_marker(self):
        f = self.run_case("leaky")
        bodies = self.ws.probe.transport.bodies
        writes = [b for b in bodies if b"pta" in b]
        self.assertEqual(len(writes), 5, writes)
        # 所有写请求的 body 必须逐字相同：随机 nonce 会让它们变成 N 个不同操作
        self.assertEqual(len(set(writes)), 1, writes)
        self.assertEqual(f.status, "confirmed")

    def test_denied_by_server_is_not_a_confirmation(self):
        f = self.run_case("deny")
        self.assertEqual(f.status, "refuted")
        self.assertLessEqual(f.confidence, 0.15)

    def test_burst_size_follows_template(self):
        f = self.run_case("leaky", burst=3)
        self.assertEqual(f.verdict["metrics"]["burst"], 3)
        self.assertEqual(f.requests_used, 4)      # 1 基线 + 3 并发

    def test_evidence_keeps_every_burst_response(self):
        f = self.run_case("leaky")
        # 5 条并发响应各自入库（label 带 #i），外加基线
        self.assertGreaterEqual(len(f.evidence_ids), 6)

    def test_replay_is_stable(self):
        # 同一候选重跑：固定 nonce → 请求体不变，证据 id 也不会因为随机标记漂移
        f1 = self.run_case("leaky")
        first = set(self.ws.probe.transport.bodies)
        f2 = self.run_case("leaky")
        second = set(self.ws.probe.transport.bodies)
        self.assertEqual(first, second)
        self.assertEqual(f1.status, f2.status)


class TemplateMetaTest(unittest.TestCase):
    def test_template_registered_and_lint_clean(self):
        raw = [t for t in vhx.TEMPLATES if t["id"] == "race-condition-idempotency"][0]
        self.assertEqual(vhx.lint(raw), [])
        self.assertEqual(raw["side_effect_level"], "L2")
        self.assertTrue(raw["requires_approval"])
        self.assertIn("concurrent_burst", raw["probe"]["sequence"])

    def test_oracle_registered(self):
        self.assertIn("idempotency_violation", ORACLE_REGISTRY)
        self.assertEqual(ORACLE_REGISTRY["idempotency_violation"]().min_level, "L2")


if __name__ == "__main__":
    unittest.main()
