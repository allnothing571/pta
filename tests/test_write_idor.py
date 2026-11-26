"""写入型越权（idor-write-object + write_effect_visible）。

三段证据：baseline（属主读原样）→ probe（攻击者写）→ verify（属主回读）。
少一段都不判，写入身份等于属主身份也不判。
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta import vhx  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.oracles import Observation, ORACLE_REGISTRY  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockTransport, RawResponse  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
ENG = "ENG-W"


def obs(role, body, status=200, identity="B", method="GET", sha=None):
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    return Observation(role=role, evidence_id="ev-%s-%s" % (role, status), identity=identity,
                       method=method, url="http://app.test/api/items/3", status=status,
                       content_type="application/json",
                       body_sha256=sha or ("%064x" % (hash(raw) & ((1 << 256) - 1))),
                       body_len=len(raw), body=raw, headers=(("Content-Type", "application/json"),))


def verdict(roles, **args):
    o = ORACLE_REGISTRY["write_effect_visible"]()
    return o.run(roles, o.Args(**args))


BASE = json.dumps({"id": 3, "name": "widget", "owner": "B"}, sort_keys=True)
MARK = '{"id":3,"name":"ptaab12cd34","owner":"B"}'
MARK2 = '{"id":3,"name":"ptaxyz98765","owner":"B"}'


class OracleTest(unittest.TestCase):
    def test_three_pieces_confirm(self):
        v = verdict([obs("baseline", BASE), obs("probe", "", 204, identity="A", method="PUT"),
                     obs("verify", MARK)])
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.90)
        self.assertIn("name", v.metrics["marker_keys"])

    def test_missing_verify_is_not_evidence(self):
        v = verdict([obs("baseline", BASE), obs("probe", "", 204, identity="A", method="PUT")])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("verify", v.missing_evidence)
        self.assertIn("回读", v.rationale)

    def test_write_denied(self):
        v = verdict([obs("baseline", BASE), obs("probe", "no", 403, identity="A", method="PUT"),
                     obs("verify", BASE)])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)

    def test_write_accepted_but_nothing_changed(self):
        v = verdict([obs("baseline", BASE), obs("probe", "", 204, identity="A", method="PUT"),
                     obs("verify", BASE)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.15)

    def test_change_without_marker_is_not_attributable(self):
        v = verdict([obs("baseline", BASE),
                     obs("probe", "", 204, identity="A", method="PUT"),
                     obs("verify", '{"id":3,"name":"someone-else","owner":"B"}')])
        self.assertFalse(v.passed)
        self.assertIn("不可归因", v.rationale)

    def test_same_identity_is_not_idor(self):
        v = verdict([obs("baseline", BASE, identity="A"),
                     obs("probe", "", 204, identity="A", method="PUT"),
                     obs("verify", MARK, identity="A")])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.20)
        self.assertIn("自写自读", v.rationale)

    def test_baseline_already_has_marker(self):
        v = verdict([obs("baseline", MARK2), obs("probe", "", 204, identity="A", method="PUT"),
                     obs("verify", MARK)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.10)

    def test_too_many_changes_backs_off(self):
        noisy = json.dumps({("k%d" % i): ("pta%08d" % i) for i in range(12)})
        v = verdict([obs("baseline", BASE), obs("probe", "", 204, identity="A", method="PUT"),
                     obs("verify", noisy)])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.55)

    def test_non_json_verify(self):
        v = verdict([obs("baseline", BASE), obs("probe", "", 204, identity="A", method="PUT"),
                     obs("verify", "<html>oops</html>")])
        self.assertFalse(v.passed)
        self.assertLessEqual(v.confidence, 0.15)


class ObjectServer(MockTransport):
    """一台有状态的"对象服务器"：GET 读当前状态，PUT 只在有权限时改 name。"""

    def __init__(self, mode="vuln"):
        super().__init__([])
        self.mode = mode
        self.state = {"id": 3, "name": "widget", "owner": "B"}
        self.writes = 0

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        identity = ""
        for k, v in req.headers:
            if k.lower() == "authorization":
                identity = v
        t0 = time.perf_counter()
        status, body = 200, json.dumps(self.state, sort_keys=True).encode("utf-8")
        if req.method.upper() in ("PUT", "PATCH", "POST"):
            self.writes += 1
            if self.mode == "deny" or (identity != "Bearer A" and self.mode != "allowall"):
                status, body = 403, b'{"error":"forbidden"}'
            elif self.mode == "reject":
                status, body = 422, b'{"error":"unknown field"}'
            else:
                try:
                    data = json.loads((req.body or b"{}").decode("utf-8"))
                except ValueError:
                    data = {}
                if self.mode != "ignore" and isinstance(data.get("name"), str):
                    self.state["name"] = data["name"]
                status, body = 204, b""
        headers = (("Content-Type", "application/json"),) if body else ()
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1", headers=headers, body=body,
                           t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


class ExecutorTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pta-write-")
        init_workspace(self.root, Scope(engagement_id=ENG, domains=("app.test",),
                                        allow_private=True, rate_per_host=200, max_requests=200))
        self.ws = open_workspace(self.root, transport=ObjectServer("vuln"),
                                 dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        self.ws.vault.put("cred/A/authorization", "Bearer A")
        self.ws.vault.put("cred/B/authorization", "Bearer B")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_case(self, mode="vuln", probe="A", baseline="B", approve=True):
        # ProbeTool 在构造时就抓住了 transport 引用，换对象不生效 —— 改它的 mode
        srv = self.ws.probe.transport
        srv.mode = mode
        srv.state = {"id": 3, "name": "widget", "owner": "B"}
        srv.writes = 0
        if approve:
            self.ws.gate.decide(ENG, "http_probe", "app.test", "body:*", "write_marker",
                                "L2", "approve", scope="class")
        eng = Executor(self.ws.probe, self.ws.store, ENG)
        tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == "idor-write-object"][0])
        target = Target(url="http://app.test/api/items/3", method="PUT", param_path="body:*",
                        identity_baseline=baseline, identity_probe=probe,
                        body_json={"name": "widget"})
        return eng.run(tpl, target)

    def test_confirmed_with_three_requests(self):
        f = self.run_case()
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.90)
        self.assertEqual(len(f.evidence_ids), 3)
        roles = self.ws.store.timings  # noqa: F841  (保持 ws 存活)
        self.assertIn("name", f.verdict["metrics"]["marker_keys"])

    def test_write_ignored_by_server(self):
        f = self.run_case(mode="ignore")
        self.assertEqual(f.status, "refuted")
        self.assertLessEqual(f.confidence, 0.20)

    def test_write_rejected_422(self):
        f = self.run_case(mode="reject")
        self.assertEqual(f.status, "refuted")
        self.assertEqual(f.confidence, 0.0)

    def test_write_forbidden(self):
        f = self.run_case(mode="deny")
        self.assertEqual(f.status, "refuted")
        self.assertEqual(f.confidence, 0.0)

    def test_same_identity_does_not_confirm(self):
        f = self.run_case(probe="B", baseline="B")
        self.assertEqual(f.status, "refuted")
        self.assertLessEqual(f.confidence, 0.20)

    def test_write_accepted_with_owner_identity_scores_low(self):
        f = self.run_case(mode="allowall", probe="B", baseline="B")
        self.assertEqual(f.status, "refuted")
        self.assertAlmostEqual(f.confidence, 0.20)
        self.assertIn("自写自读", f.verdict["rationale"])

    def test_unapproved_does_not_send_write(self):
        f = self.run_case(approve=False)
        self.assertEqual(f.status, "pending_approval")
        transport = self.ws.probe.transport
        self.assertEqual(transport.writes, 0)

    def test_critic_keeps_it(self):
        f = self.run_case()
        self.assertEqual(f.status, "confirmed")
        crit = Critic(self.ws).review_finding(f, apply=False)
        self.assertEqual(crit.status, "kept", crit.to_json())


class TemplateMetaTest(unittest.TestCase):
    def test_template_is_registered_and_lint_clean(self):
        raw = [t for t in vhx.TEMPLATES if t["id"] == "idor-write-object"][0]
        self.assertEqual(vhx.lint(raw), [])
        self.assertEqual(raw["side_effect_level"], "L2")
        self.assertTrue(raw["requires_approval"])
        self.assertEqual(raw["oracle"]["name"], "write_effect_visible")
        self.assertEqual(raw["probe"]["verify_after"]["method"], "GET")

    def test_payload_class_registered(self):
        from pta import payloads
        self.assertIn("write_marker", payloads.REGISTRY)
        self.assertEqual(payloads.level_floor("write_marker"), "L2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
