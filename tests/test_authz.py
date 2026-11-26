"""缺失授权：authz_template_diff 判定 + authz-missing-endpoint 端到端。

核心命题：无凭据拿到与授权视角等价的数据，才算缺失授权。
两条反证必须拦住：一是被拒（401/403/跳登录），二是返回的其实是拒绝模板本身。
"""
import copy
import hashlib
import json
import unittest

from pta import vhx
from pta.critic import Critic
from pta.executor import Executor, Target
from pta.oracles import AuthzTemplateDiff, Observation
from pta.transport import MockRoute
from support import WorkspaceCase

DATA = (b'{"orders":[{"id":1001,"amount":88.5,"status":"shipped"},'
        b'{"id":1002,"amount":12.0,"status":"open"}],"user":"alice"}')
DENY403 = b'{"error":"forbidden","message":"admin role required"}'
LOGIN = (b'<!doctype html><html><head><title>Sign in</title></head><body>'
         b'<form action="/login" method="post"><input name="username">'
         b'<input name="password"><button>Log in</button></form></body></html>')
OTHER = b'{"items":[{"sku":"A-1","qty":2}],"total":14,"currency":"USD"}'


def obs(role, body, status=200, identity="A"):
    return Observation(role=role, evidence_id="ev-" + role + "-" + identity,
                       identity=identity, method="GET", url="http://app.test/api/orders",
                       status=status, content_type="application/json",
                       body_sha256=hashlib.sha256(body).hexdigest(),
                       body_len=len(body), body=body, headers={})


class OracleTest(unittest.TestCase):
    def run_oracle(self, observations, **args):
        return AuthzTemplateDiff().run(observations, AuthzTemplateDiff.Args(**args))

    def test_confirmed_with_deny_template(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DATA, identity="none"),
                             obs("control", DENY403, status=403, identity="none")])
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.90)
        self.assertTrue(v.metrics["deny_template"])

    def test_confirmed_without_deny_template_is_slightly_lower(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DATA, identity="none")])
        self.assertTrue(v.passed)
        self.assertAlmostEqual(v.confidence, 0.88, places=2)
        self.assertFalse(v.metrics["deny_template"])

    def test_require_deny_template_downgrades_to_hypothesis(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DATA, identity="none")],
                            require_deny_template=True)
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.60, places=2)
        self.assertIn("control", v.missing_evidence)

    def test_probe_equal_to_deny_template_is_refuted(self):
        # 未登录也返回 200，但返回的就是 403 页面本身（很多框架这么干）
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DENY403, identity="none"),
                             obs("control", DENY403, status=403, identity="none")])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.10, places=2)
        self.assertIn("拒绝模板", v.rationale)

    def test_denied_status_is_refuted(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DENY403, status=401, identity="none")])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)

    def test_redirect_to_login_is_refuted(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", b"", status=302, identity="none")])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("重定向", v.rationale)

    def test_no_baseline_is_hypothesis(self):
        v = self.run_oracle([obs("probe", DATA, identity="none")])
        self.assertFalse(v.passed)
        self.assertAlmostEqual(v.confidence, 0.55, places=2)
        self.assertIn("baseline", v.missing_evidence)

    def test_same_identity_is_refuted(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DATA, identity="A")])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("同一身份", v.rationale)

    def test_different_content_is_refuted(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", OTHER, identity="none"),
                             obs("control", DENY403, status=403, identity="none")])
        self.assertFalse(v.passed)
        self.assertLess(v.confidence, 0.2)

    def test_missing_probe(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A")])
        self.assertFalse(v.passed)
        self.assertIn("probe", v.missing_evidence)

    def test_names_the_identity_it_actually_used(self):
        # 真靶场上踩到的：probe 用的是身份 B 的 cookie，结论却写「无凭据拿到数据」。
        # 报告上这一句会被当成"不用登录就能读"，判断方向直接跑偏。
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DATA, identity="B")])
        self.assertTrue(v.passed)
        self.assertIn("身份 B 的请求", v.rationale)
        self.assertNotIn("无凭据", v.rationale)
        self.assertFalse(v.metrics["probe_anonymous"])

    def test_anonymous_probe_keeps_the_no_credential_wording(self):
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DATA, identity="none")])
        self.assertTrue(v.passed)
        self.assertIn("无凭据请求", v.rationale)
        self.assertTrue(v.metrics["probe_anonymous"])

    def test_identical_bytes_across_two_identities_is_called_out(self):
        # WebGoat 的 /service/labels.mvc：两个账号拿到同一份字节，其实是全局共享数据。
        # 判定仍然成立（可能是真的越权），但必须把"这也可能是人人可读"说出来。
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DATA, identity="B")])
        self.assertTrue(v.metrics["identical_bytes_across_identities"])
        self.assertIn("全局共享资源", v.rationale)

    def test_different_bytes_across_two_identities_is_not_called_out(self):
        # 内容随身份变化（哪怕只有一点点），就说明这条接口是按身份出数据的，
        # 不该再挂"可能是共享资源"的免责声明，否则每个真越权都自带一句废话。
        v = self.run_oracle([obs("baseline", DATA, identity="A"),
                             obs("probe", DATA.replace(b"alice", b"alicf"), identity="B")])
        self.assertTrue(v.passed, v.rationale)
        self.assertNotIn("identical_bytes_across_identities", v.metrics)
        self.assertNotIn("全局共享资源", v.rationale)


class ExecutorTest(WorkspaceCase):
    def routes(self, probe_body=DATA, probe_status=200, probe_headers=()):
        return [
            # 授权身份：能读到订单
            MockRoute("GET", "app.test", "/api/orders", 200,
                      (("Content-Type", "application/json"),), DATA,
                      identity="Bearer TOKEN-A"),
            # 无凭据：漏洞版本照样返回数据
            MockRoute("GET", "app.test", "/api/orders", probe_status,
                      (("Content-Type", "application/json"),) + tuple(probe_headers),
                      probe_body, identity=""),
            # 兄弟接口：无凭据必然 403，用来取拒绝模板
            MockRoute("GET", "app.test", "/admin/audit", 403,
                      (("Content-Type", "application/json"),), DENY403, identity=""),
        ]

    def run_tpl(self, ws, control_url="http://app.test/admin/audit", probe="none"):
        tpl = vhx.load(copy.deepcopy(
            [t for t in vhx.TEMPLATES if t["id"] == "authz-missing-endpoint"][0]))
        target = Target(url="http://app.test/api/orders", identity_baseline="A",
                        identity_probe=probe, control_url=control_url)
        return Executor(ws.probe, ws.store, "ENG-T").run(tpl, target)

    def test_missing_authz_confirmed_with_control(self):
        ws = self.make_ws(self.routes(), domains=("app.test",))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.90)
        self.assertEqual(len(f.evidence_ids), 3)   # baseline + control + probe

    def test_confirmed_without_control_url(self):
        ws = self.make_ws(self.routes(), domains=("app.test",))
        f = self.run_tpl(ws, control_url=None)
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertAlmostEqual(f.confidence, 0.88, delta=0.02)
        self.assertEqual(len(f.evidence_ids), 2)

    def test_login_page_200_is_refuted(self):
        ws = self.make_ws(self.routes(probe_body=LOGIN, probe_status=200,
                                      probe_headers=(("Content-Type", "text/html"),)),
                          domains=("app.test",))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertLess(f.confidence, 0.2)

    def test_401_is_refuted(self):
        ws = self.make_ws(self.routes(probe_body=DENY403, probe_status=401),
                          domains=("app.test",))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertEqual(f.confidence, 0.0)

    def test_redirect_to_login_is_refuted(self):
        ws = self.make_ws(self.routes(probe_body=b"", probe_status=302,
                                      probe_headers=(("Location", "/login"),)),
                          domains=("app.test",))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertEqual(f.confidence, 0.0)

    def test_control_denied_is_logged_as_evidence(self):
        ws = self.make_ws(self.routes(), domains=("app.test",))
        f = self.run_tpl(ws)
        rows = [ws.store.get_evidence_row(i) for i in f.evidence_ids]
        statuses = sorted(r["status"] for r in rows)
        self.assertEqual(statuses, [200, 200, 403])

    def test_critic_keeps_confirmed_pairing(self):
        ws = self.make_ws(self.routes(), domains=("app.test",))
        f = self.run_tpl(ws)
        crit = Critic(ws).review_finding(f)
        self.assertEqual(crit.status, "kept", json.dumps(crit.to_json(), ensure_ascii=False))

    def test_template_meta(self):
        tpl = vhx.load(copy.deepcopy(
            [t for t in vhx.TEMPLATES if t["id"] == "authz-missing-endpoint"][0]))
        self.assertEqual(vhx.lint(tpl.raw), [])
        self.assertEqual(tpl.raw["side_effect_level"], "L1")
        self.assertEqual(tpl.raw["oracle"]["name"], "authz_template_diff")


if __name__ == "__main__":
    unittest.main()
