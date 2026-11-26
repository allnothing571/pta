"""F 项第二项：业务逻辑边界（越界数值被接受）。

判据不是"接口返回 200"，而是**回读里原样出现了那个值**。三层测试：
  1) 载荷层 —— numeric 类塞进去的是 JSON 数字，不是字符串；
  2) oracle 单测 —— 手工造 Observation，把每条降级分支钉住；
  3) 端到端 —— 自己写 Transport（要按请求体内容分态），跑完整 Executor，
     确认「接受 / 422 拒绝 / 夹紧为 0」三种服务端行为分得开。
"""
from __future__ import annotations

import json
import unittest
from typing import Any, Dict, List, Tuple

from pta import payloads, vhx
from pta.executor import Executor, Target
from pta.models import RawResponse
from pta.oracles import NumericBoundaryAccepted, Observation
from pta.transport import Transport
from pta.workspace import open_workspace
from support import WorkspaceCase, fake_dns

ENG = "ENG-T"  # 必须与 WorkspaceCase 里 Scope 的 engagement_id 一致


def obs(role: str, status: int, body: bytes = b"{}", ctype: str = "application/json",
        identity: str = "A", method: str = "POST", url: str = "http://app.test/api/x",
        eid: str = "") -> Observation:
    return Observation(role=role, evidence_id=eid or "%s-%d" % (role, status),
                       identity=identity, method=method, url=url, status=status,
                       content_type=ctype, body_sha256="0" * 64, body_len=len(body),
                       body=body)


def _resp(status: int, body: bytes = b"{}",
          ctype: str = "application/json") -> RawResponse:
    return RawResponse(status=status, reason="x", http_version="HTTP/1.1",
                       headers=(("Content-Type", ctype),), body=body,
                       t_send=0.0, t_first_byte=0.0, t_end=0.0)


# ----------------------------------------------------------- 载荷层：塞的是数字
class PayloadTest(unittest.TestCase):
    def test_negative_and_huge_are_numeric(self):
        for name in ("negative_number", "huge_number"):
            cls = payloads.REGISTRY[name]
            self.assertTrue(cls.numeric, "%s 必须是 numeric，否则塞进去是字符串" % name)
            self.assertEqual(cls.level_floor, "L2")

    def test_render_values(self):
        self.assertEqual(payloads.render("negative_number"), "-100")
        self.assertEqual(payloads.render("huge_number"), "999999999")


# ---------------------------------------------------------------- oracle 单测
class OracleTest(unittest.TestCase):
    def judge(self, observations, expect="-100"):
        return NumericBoundaryAccepted().run(
            observations, NumericBoundaryAccepted.Args(expect_value=expect))

    def test_value_readback_means_accepted(self):
        v = self.judge([obs("baseline", 200),
                        obs("probe", 200),
                        obs("verify", 200, b'{"balance": 900, "last_amount": -100}',
                            method="GET")])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.86, places=2)
        self.assertIn("-100", v.rationale)

    def test_rejected_by_validation(self):
        v = self.judge([obs("baseline", 200), obs("probe", 422,
                                                  b'{"error": "amount must be positive"}')])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.0, places=2)
        self.assertIn("范围校验", v.rationale)

    def test_value_clamped_away(self):
        v = self.judge([obs("baseline", 200),
                        obs("probe", 200),
                        obs("verify", 200, b'{"balance": 1000, "last_amount": 0}',
                            method="GET")])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.15, places=2)
        self.assertIn("夹紧", v.rationale)

    def test_no_readback_is_not_accepted(self):
        v = self.judge([obs("baseline", 200), obs("probe", 200)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.0, places=2)
        self.assertIn("写完没有回读", v.rationale)

    def test_baseline_failed(self):
        v = self.judge([obs("baseline", 401), obs("probe", 200)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.0, places=2)
        self.assertIn("不成立", v.rationale)

    def test_probe_ambiguous_status(self):
        v = self.judge([obs("baseline", 200), obs("probe", 302)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.10, places=2)


# ---------------------------------------------------------------- 端到端
class LedgerServer(Transport):
    """一个最小账本服务：POST /api/transfer 入账，GET /api/balance 回读。

    三种服务端行为：
      vuln   照单全收（负数也进账）；
      strict 金额 <= 0 直接 422；
      clamp  负数改成 0 再存（看起来 200，其实没存那个值）。
    """
    name = "ledger-mock"

    def __init__(self, mode: str = "vuln") -> None:
        self.mode = mode
        self.balance = 1000
        self.last_amount: object = None
        self.sent: List[Dict[str, Any]] = []
        self.amounts: List[object] = []

    def send(self, req, timeout_s: float = 10.0) -> RawResponse:
        hdrs = {k.lower(): v for k, v in req.headers}
        if not hdrs.get("authorization"):
            return _resp(401, b'{"error": "unauthorized"}')
        if req.method == "GET":
            body = json.dumps({"balance": self.balance,
                               "last_amount": self.last_amount}).encode()
            return _resp(200, body)
        data = json.loads((req.body or b"{}").decode() or "{}")
        amount = data.get("amount")
        self.amounts.append(amount)
        self.sent.append(data)
        if self.mode == "strict" and not (isinstance(amount, int) and amount > 0):
            return _resp(422, b'{"error": "amount must be positive"}')
        if self.mode == "clamp" and isinstance(amount, int) and amount < 0:
            amount = 0
        self.last_amount = amount
        self.balance += amount if isinstance(amount, int) else 0
        return _resp(200, json.dumps({"ok": True, "amount": amount}).encode())


class EndToEndTest(WorkspaceCase):
    def _ws(self, transport):
        return self.make_ws([], transport=transport)

    @staticmethod
    def _approve(ws, param_path="body:amount", payload_class="negative_number"):
        ws.gate.decide(ENG, "http_probe", "app.test", param_path, payload_class,
                       "L2", "approve", scope="class")

    @staticmethod
    def _tpl(tid="logic-negative-amount"):
        return vhx.load([t for t in vhx.TEMPLATES if t["id"] == tid][0])

    def _target(self):
        return Target(url="http://app.test/api/transfer", method="POST",
                      param_path="body:amount", identity_baseline="A",
                      identity_probe="A", body_json={"to": "bob", "amount": 1},
                      verify_url="http://app.test/api/balance")

    def test_negative_accepted_is_confirmed(self):
        srv = LedgerServer("vuln")
        ws = self._ws(srv)
        self._approve(ws)
        f = Executor(ws.probe, ws.store, ENG).run(self._tpl(), self._target())
        self.assertEqual(f.status, "confirmed", f.verdict.get("rationale"))
        self.assertAlmostEqual(f.confidence, 0.86, places=2)
        # 服务端收到的是数字 -100，不是字符串 "-100"
        self.assertEqual(srv.amounts, [1, -100])
        self.assertIsInstance(srv.amounts[1], int)
        # 回读发生在写入之后，且回读命中的是存下来的值
        self.assertEqual(srv.sent[-1]["amount"], -100)
        self.assertEqual(srv.last_amount, -100)

    def test_validation_rejects_is_refuted(self):
        srv = LedgerServer("strict")
        ws = self._ws(srv)
        self._approve(ws)
        f = Executor(ws.probe, ws.store, ENG).run(self._tpl(), self._target())
        self.assertEqual(f.status, "refuted", f.verdict.get("rationale"))
        self.assertAlmostEqual(f.confidence, 0.0, places=2)
        self.assertIn("范围校验", f.verdict.get("rationale", ""))

    def test_clamped_value_is_refuted_not_confirmed(self):
        srv = LedgerServer("clamp")
        ws = self._ws(srv)
        self._approve(ws)
        f = Executor(ws.probe, ws.store, ENG).run(self._tpl(), self._target())
        self.assertEqual(f.status, "refuted", f.verdict.get("rationale"))
        self.assertAlmostEqual(f.confidence, 0.15, places=2)
        self.assertIn("夹紧", f.verdict.get("rationale", ""))
        # 接口回了 200，但存下来的是 0
        self.assertEqual(srv.amounts[1], -100)
        self.assertEqual(srv.last_amount, 0)


if __name__ == "__main__":
    unittest.main()
