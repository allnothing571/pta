"""批量赋值：field_escalation_effect 单元 + 执行链（含 L2 审批）+ 模板元数据。"""
from __future__ import annotations

import copy
import json
import time
import unittest
from typing import Any, Dict, List, Optional, Sequence

from pta import oracles, vhx
from pta.critic import Critic
from pta.executor import Executor, Target
from pta.oracles import FieldEscalationEffect, Observation
from pta.transport import RawResponse, Transport
from support import WorkspaceCase

BASE_BODY = b'{"id":7,"name":"alice","role":"user","is_admin":false}'
ADMIN_BODY = b'{"id":7,"name":"alice","role":"admin","is_admin":true}'
URL = "http://app.test/api/profile"


def obs(role: str, body: bytes, status: int = 200, identity: str = "A") -> Observation:
    return Observation(
        role=role, evidence_id="ev-%s" % role, identity=identity, method="POST",
        url=URL, status=status, content_type="application/json",
        body_sha256="sha-%s" % role, body_len=len(body), body=body,
    )


def judge(observations: Sequence[Observation], **kwargs: Any):
    return FieldEscalationEffect().run(
        observations, FieldEscalationEffect.Args(**kwargs))


class OracleTest(unittest.TestCase):
    def test_missing_probe(self):
        v = judge([])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("probe", v.missing_evidence)

    def test_probe_rejected_by_permission(self):
        v = judge([obs("baseline", BASE_BODY), obs("probe", b'{"error":"nope"}', 403)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("403", v.rationale)

    def test_probe_rejected_by_validation(self):
        v = judge([obs("baseline", BASE_BODY), obs("probe", b'{"error":"bad"}', 422)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("422", v.rationale)

    def test_missing_baseline(self):
        v = judge([obs("probe", ADMIN_BODY)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.55, delta=0.01)
        self.assertIn("baseline", v.missing_evidence)

    def test_escalation_confirmed(self):
        v = judge([obs("baseline", BASE_BODY), obs("probe", ADMIN_BODY)])
        self.assertTrue(v.passed, v.rationale)
        self.assertGreaterEqual(v.confidence, 0.90)
        self.assertEqual(v.metrics["baseline_rank"], 1)
        self.assertEqual(v.metrics["probe_rank"], 3)
        self.assertEqual(v.metrics["delta"], 2)
        self.assertIn("role", str(v.metrics["probe_fields"]))

    def test_flag_field_counts_as_escalation(self):
        body_ok = b'{"id":7,"is_admin":false}'
        body_bad = b'{"id":7,"is_admin":true}'
        v = judge([obs("baseline", body_ok), obs("probe", body_bad)])
        self.assertTrue(v.passed, v.rationale)
        self.assertEqual(v.metrics["delta"], 3)

    def test_numeric_level_field(self):
        v = judge([obs("baseline", b'{"privilege_level":1}'),
                   obs("probe", b'{"privilege_level":5}')])
        self.assertTrue(v.passed, v.rationale)
        self.assertEqual(v.metrics["delta"], 4)

    def test_field_ignored_no_delta(self):
        v = judge([obs("baseline", BASE_BODY), obs("probe", BASE_BODY)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.20, delta=0.01)
        self.assertIn("没有提升", v.rationale)

    def test_field_dropped_from_response(self):
        v = judge([obs("baseline", BASE_BODY), obs("probe", b'{"id":7,"name":"alice"}')])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.15)
        self.assertIn("probe:privilege_field", v.missing_evidence)

    def test_non_json_body_is_unknown(self):
        v = judge([obs("baseline", b"<html>ok</html>"), obs("probe", b"<html>ok</html>")])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.15)

    def test_require_delta_false_keeps_weak_signal(self):
        v = judge([obs("baseline", BASE_BODY), obs("probe", BASE_BODY)],
                  require_privilege_delta=False)
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.55, delta=0.01)

    def test_nested_and_custom_fields(self):
        v = judge([obs("baseline", b'{"user":{"role":"member"}}'),
                   obs("probe", b'{"user":{"role":"superadmin"}}')])
        self.assertTrue(v.passed, v.rationale)
        self.assertIn("user.role", v.metrics["probe_fields"])


class BodyAwareTransport(Transport):
    """按请求体里有没有权限字段来决定返回什么：真正模拟"字段被写库/被忽略/被拒绝"。"""

    name = "body-aware"

    def __init__(self, mode: str = "vuln", require_name: bool = True) -> None:
        self.mode = mode
        self.require_name = require_name
        self.sent: List[Any] = []

    def send(self, req: Any, timeout_s: float = 10.0) -> RawResponse:
        self.sent.append(req)
        try:
            data = json.loads((req.body or b"{}").decode("utf-8"))
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        escalated = (str(data.get("role", "")).lower() in ("admin", "administrator")
                     or data.get("is_admin") in (True, "true", 1))
        status, body = 200, BASE_BODY
        if self.require_name and "name" not in data:
            status, body = 400, b'{"error":"name is required"}'
        elif escalated:
            if self.mode == "vuln":
                body = ADMIN_BODY
            elif self.mode == "reject":
                status, body = 422, b'{"error":"unknown field role"}'
            else:                       # ignore：接受请求但把字段丢掉
                body = BASE_BODY
        t = time.monotonic()
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),),
                           body=body, t_send=t, t_first_byte=t, t_end=time.monotonic())


def template() -> Any:
    return vhx.load(copy.deepcopy(
        [t for t in vhx.TEMPLATES if t["id"] == "mass-assignment-privilege"][0]))


class ExecutorTest(WorkspaceCase):
    CORPUS = {"name": "alice"}

    def run_tpl(self, ws, approve: bool = True, body_json: Optional[Dict[str, Any]] = None):
        if approve:
            ws.gate.decide("ENG-T", "http_probe", "app.test", "body:*", "extra_field",
                           "L2", "approve", scope="class")
        target = Target(url=URL, method="POST", param_path="body:*",
                        identity_baseline="A", identity_probe="A",
                        body_json=body_json if body_json is not None else dict(self.CORPUS))
        return Executor(ws.probe, ws.store, "ENG-T").run(template(), target)

    def test_confirmed_when_field_written(self):
        ws = self.make_ws([], transport=BodyAwareTransport("vuln"))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.90)
        self.assertEqual(len(f.evidence_ids), 2)          # baseline + probe
        self.assertEqual(f.verdict["metrics"]["delta"], 2)
        crit = Critic(ws).review_finding(f)
        self.assertEqual(crit.status, "kept", crit.blocks)

    def test_l2_needs_approval_first(self):
        ws = self.make_ws([], transport=BodyAwareTransport("vuln"))
        f = self.run_tpl(ws, approve=False)
        self.assertTrue(f.stop_reason.startswith("pending_approval"), f.stop_reason)
        self.assertEqual(f.evidence_ids, [])
        # baseline 是关键请求（无载荷，L1）先发了；probe 被门挡住，没有任何写入
        self.assertEqual(len(ws.store.list_evidence("ENG-T")), 1)

    def test_field_ignored_is_refuted(self):
        ws = self.make_ws([], transport=BodyAwareTransport("ignore"))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertLess(f.confidence, 0.30)

    def test_server_rejects_field(self):
        ws = self.make_ws([], transport=BodyAwareTransport("reject"))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertEqual(f.confidence, 0.0)

    def test_without_corpus_baseline_fails(self):
        ws = self.make_ws([], transport=BodyAwareTransport("vuln"))
        f = self.run_tpl(ws, body_json={})
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertEqual(f.confidence, 0.0)
        self.assertIn("400", f.verdict["rationale"])   # 缺合法字段，写入被拒

    def test_probe_body_really_contains_extra_field(self):
        tx = BodyAwareTransport("vuln")
        ws = self.make_ws([], transport=tx)
        self.run_tpl(ws)
        bodies = [json.loads(r.body.decode("utf-8")) for r in tx.sent]
        self.assertEqual(bodies[0], {"name": "alice"})       # baseline 原样
        self.assertEqual(bodies[1]["name"], "alice")         # probe 保留合法字段
        self.assertEqual(bodies[1]["role"], "admin")
        self.assertTrue(bodies[1]["is_admin"])


class TemplateMetaTest(unittest.TestCase):
    def test_template_shape(self):
        t = template()
        self.assertEqual(t.id, "mass-assignment-privilege")
        self.assertEqual(t.side_effect_level, "L2")
        self.assertTrue(t.requires_approval)
        self.assertEqual(t.oracle["name"], "field_escalation_effect")
        self.assertIn("field_escalation_effect", oracles.ORACLE_REGISTRY)

    def test_lint_clean(self):
        self.assertEqual(vhx.lint(copy.deepcopy(
            [t for t in vhx.TEMPLATES if t["id"] == "mass-assignment-privilege"][0])), [])

    def test_payload_class_registered(self):
        from pta import payloads
        self.assertIn("extra_field", payloads.REGISTRY)


if __name__ == "__main__":
    unittest.main()
