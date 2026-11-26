"""真靶场回归：判定链跑在真实 socket 上（range_target.py）。

和别的测试文件不同，这里没有 MockTransport——每个断言背后都是一个真的 HTTP 请求，
打到真的 sqlite / 真的 SSRF 转发。它守的是"mock 看不出来的东西"：

- 载荷在原值后面追加（`?id=1'`），而不是整段替换（`?id='` 会让真假两个条件都返回空集）；
- `Content-Length`/query 转义、连接关闭、读超时这些只在真 socket 上才出错；
- SQLite 的错误文案要能被 `error_signature_match` 认出来。

时间盲注不放进来：SLEEP(2) × 12 次要十几秒，`demo_range.py` 里跑（那也是它唯一慢的一条）。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

from pta import overrides as ov
from pta.critic import Critic
from pta.executor import Executor, Target
from pta.scope import Scope
from pta.workspace import init_workspace, open_workspace

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import range_target  # noqa: E402

ENG = "ENG-RANGE-T"


def tearDownModule():
    if RangeCase.httpd is not None:
        RangeCase.httpd.shutdown()
        RangeCase.httpd.server_close()
    if RangeCase.docker is not None:
        RangeCase.docker.shutdown()
        RangeCase.docker.server_close()


class RangeCase(unittest.TestCase):
    httpd = None
    docker = None
    port = 0

    # 靶场只起一次：每个测试类各起一次会在 Windows 上撞 SO_REUSEADDR 端口劫持
    # （旧 server 已 shutdown 但没 server_close，socket 还占着端口，新连接被它吞掉）。
    @classmethod
    def setUpClass(cls):
        if RangeCase.httpd is None:
            RangeCase.httpd, RangeCase.docker, RangeCase.port = range_target.start(0, 2375)
        cls.httpd = RangeCase.httpd
        cls.docker = RangeCase.docker
        cls.port = RangeCase.port
        cls.base = "http://127.0.0.1:%d" % cls.port

    def setUp(self):
        self.tmp = os.path.join(tempfile.mkdtemp(prefix="pta-range-test-"), "eng")
        init_workspace(self.tmp, Scope(engagement_id=ENG, domains=("127.0.0.1",),
                                       allow_private=True, allowed_ports=(self.port,),
                                       max_requests=200, rate_per_host=1000.0))
        self.ws = open_workspace(self.tmp)
        self.ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
        self.ws.vault.put("cred/B/authorization", "Bearer TOKEN-B")

    def tearDown(self):
        shutil.rmtree(os.path.dirname(self.tmp), ignore_errors=True)

    # ---- 跑一个模板 ---------------------------------------------------------
    def run_tpl(self, template_id, url, *, param=None, method="GET", body=None,
                base="A", probe="A", id_plus_one=None, approvals=()):
        for pp, pc in approvals:
            self.ws.gate.decide(ENG, "http_probe", "127.0.0.1", pp, pc, "L2", "approve",
                                scope="class")
        tpl, _frag = ov.load_template(self.ws, template_id)
        target = Target(url=url, param_path=param, method=method, body_json=body,
                        identity_baseline=base, identity_probe=probe,
                        id_plus_one=id_plus_one)
        finding = Executor(self.ws.probe, self.ws.store, ENG).run(tpl, target)
        crit = Critic(self.ws).review_finding(finding, apply=False)
        return finding, crit


class SqliErrorTest(RangeCase):
    def test_vulnerable_endpoint_confirms(self):
        f, crit = self.run_tpl("sqli-error-boolean", self.base + "/api/items?id=1",
                               param="query:id")
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.85)
        self.assertIn("sqlite", str(f.verdict["metrics"]))
        self.assertEqual(crit.status, "kept", crit.blocks)

    def test_same_payload_against_parameterized_query_refutes(self):
        # 同一份载荷、同一份数据，只有实现方式不同（参数化）→ 必须判否
        f, _ = self.run_tpl("sqli-error-boolean", self.base + "/api/items_safe?id=1",
                            param="query:id")
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertLess(f.confidence, 0.20)


class SqliBooleanTest(RangeCase):
    def test_vulnerable_endpoint_confirms(self):
        f, _ = self.run_tpl("sqli-boolean-blind", self.base + "/api/items?id=1",
                            param="query:id")
        self.assertEqual(f.status, "confirmed", f.verdict)
        m = f.verdict["metrics"]
        self.assertGreaterEqual(m["similarity_true_base"], 0.90)
        self.assertLess(m["similarity_true_false"], 0.55)

    def test_safe_endpoint_refutes(self):
        f, _ = self.run_tpl("sqli-boolean-blind", self.base + "/api/items_safe?id=1",
                            param="query:id")
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertIn("几乎一致", f.verdict["rationale"])


class IdorTest(RangeCase):
    def test_cross_identity_read_confirms(self):
        f, _ = self.run_tpl("idor-object-ref", self.base + "/api/users?id=1",
                            param="query:id", base="A", probe="B", id_plus_one="1")
        self.assertEqual(f.status, "confirmed", f.verdict)

    def test_owner_check_refutes(self):
        f, _ = self.run_tpl("idor-object-ref", self.base + "/api/users_safe?id=1",
                            param="query:id", base="A", probe="B", id_plus_one="1")
        self.assertEqual(f.status, "refuted", f.verdict)


class MassAssignmentTest(RangeCase):
    def test_writable_role_confirms(self):
        f, _ = self.run_tpl("mass-assignment-privilege", self.base + "/api/profile",
                            param="body:*", method="POST", body={"name": "widget"},
                            approvals=[("body:*", "extra_field")])
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.verdict["metrics"]["delta"], 1)

    def test_whitelisted_fields_refute(self):
        f, _ = self.run_tpl("mass-assignment-privilege", self.base + "/api/profile_safe",
                            param="body:*", method="POST", body={"name": "widget"},
                            approvals=[("body:*", "extra_field")])
        self.assertEqual(f.status, "refuted", f.verdict)


class SsrfTest(RangeCase):
    def test_internal_docker_fingerprint_confirms(self):
        if self.docker is None:
            self.skipTest("127.0.0.1:2375 被占用，内网假服务没起来")
        f, _ = self.run_tpl("ssrf-internal-service", self.base + "/api/fetch?url=x",
                            param="query:url",
                            approvals=[("query:url", "internal_metadata_url"),
                                       ("query:url", "internal_docker_url"),
                                       ("query:url", "internal_etcd_url")])
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertIn("docker_api", str(f.verdict["metrics"]))

    def test_host_allowlist_refutes(self):
        f, _ = self.run_tpl("ssrf-internal-service", self.base + "/api/fetch_safe?url=x",
                            param="query:url",
                            approvals=[("query:url", "internal_metadata_url"),
                                       ("query:url", "internal_docker_url"),
                                       ("query:url", "internal_etcd_url")])
        self.assertEqual(f.status, "refuted", f.verdict)


class UnapprovedTest(RangeCase):
    def test_l2_without_approval_sends_nothing(self):
        # 真靶场上同样成立：没审批就一次注入请求都不发（只看证据条数）
        f, _ = self.run_tpl("sqli-time-blind", self.base + "/api/items?id=1",
                            param="query:id")
        self.assertTrue(f.stop_reason.startswith("pending_approval"), f.stop_reason)
        self.assertEqual(f.evidence_ids, [])


if __name__ == "__main__":
    unittest.main()
