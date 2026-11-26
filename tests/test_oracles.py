"""验收⑥：IDOR 走完全链路 → confirmed。以及负样本必须 refuted。"""
import unittest

from pta.models import verdict_status
from pta.oracles import (DifferentialObjectAccess, ErrorSignatureMatch, FileSignatureMatch,
                         build_oracle, load_observations)
from pta.probe import ProbeRequest
from pta.transport import MockRoute
from support import OBJECT_BODY, WorkspaceCase, idor_routes


class OracleTest(WorkspaceCase):
    def collect(self, ws, label):
        roles = {}
        for row in ws.store.list_evidence("ENG-T", label):
            roles[row["evidence_id"]] = row["identity"]
        return load_observations(ws.store, ws.cas, "ENG-T", label, roles)

    def test_idor_confirmed(self):
        ws = self.make_ws(idor_routes())
        base = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/users/1",
                                         identity="A", label="idor"))
        probe = ws.probe.run(ProbeRequest(action_id="2", url="http://app.test/api/users/1",
                                          identity="B", label="idor"))
        self.assertEqual((base.status, probe.status), ("ok", "ok"))

        obs = load_observations(ws.store, ws.cas, "ENG-T", "idor",
                                {base.evidence_id: "baseline", probe.evidence_id: "probe"})
        v = DifferentialObjectAccess().run(obs, DifferentialObjectAccess.Args())
        self.assertTrue(v.passed, v.rationale)
        self.assertEqual(verdict_status(v.confidence), "confirmed")

    def test_idor_negative_when_403(self):
        ws = self.make_ws(idor_routes())
        base = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/users/2",
                                         identity="A", label="idor2"))
        probe = ws.probe.run(ProbeRequest(action_id="2", url="http://app.test/api/users/2",
                                          identity="B", label="idor2"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "idor2",
                                {base.evidence_id: "baseline", probe.evidence_id: "probe"})
        v = DifferentialObjectAccess().run(obs, DifferentialObjectAccess.Args())
        self.assertFalse(v.passed)
        self.assertEqual(verdict_status(v.confidence), "refuted")

    def test_missing_evidence_is_not_exception(self):
        v = DifferentialObjectAccess().run([], DifferentialObjectAccess.Args())
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertTrue(v.missing_evidence)

    def test_decoy_with_same_body_downgrades(self):
        """服务端不看 id：读一个不存在的对象也拿到同一份内容 → 越权不成立。"""
        routes = idor_routes()
        routes.append(MockRoute("GET", "app.test", "/api/users/999999999", 200,
                                (("Content-Type", "application/json"),), OBJECT_BODY,
                                identity="Bearer TOKEN-A"))
        ws = self.make_ws(routes)
        base = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/users/1",
                                         identity="A", label="idor3"))
        probe = ws.probe.run(ProbeRequest(action_id="2", url="http://app.test/api/users/1",
                                          identity="B", label="idor3"))
        decoy = ws.probe.run(ProbeRequest(action_id="3",
                                          url="http://app.test/api/users/999999999",
                                          identity="A", label="idor3"))
        self.assertEqual(decoy.status, "ok")
        obs = load_observations(ws.store, ws.cas, "ENG-T", "idor3",
                                {base.evidence_id: "baseline", probe.evidence_id: "probe",
                                 decoy.evidence_id: "decoy"})
        v = DifferentialObjectAccess().run(obs, DifferentialObjectAccess.Args())
        self.assertFalse(v.passed, v.rationale)
        self.assertEqual(v.confidence, 0.35)
        self.assertIn("不存在的对象", v.rationale)
        self.assertIn("decoy_similarity", v.metrics)

    def test_decoy_404_keeps_confirmed(self):
        """服务端确实按 id 查（不存在的对象 404）→ 相似度证据仍然成立。"""
        routes = idor_routes()
        routes.append(MockRoute("GET", "app.test", "/api/users/999999999", 404,
                                (("Content-Type", "application/json"),),
                                b'{"error":"not found"}', identity="Bearer TOKEN-A"))
        ws = self.make_ws(routes)
        base = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/users/1",
                                         identity="A", label="idor4"))
        probe = ws.probe.run(ProbeRequest(action_id="2", url="http://app.test/api/users/1",
                                          identity="B", label="idor4"))
        decoy = ws.probe.run(ProbeRequest(action_id="3",
                                          url="http://app.test/api/users/999999999",
                                          identity="A", label="idor4"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "idor4",
                                {base.evidence_id: "baseline", probe.evidence_id: "probe",
                                 decoy.evidence_id: "decoy"})
        v = DifferentialObjectAccess().run(obs, DifferentialObjectAccess.Args())
        self.assertTrue(v.passed, v.rationale)
        self.assertEqual(v.metrics["decoy_status"], 404)

    def test_error_signature_positive(self):
        ws = self.make_ws([
            MockRoute("GET", "app.test", "/api/ok", 200, (("Content-Type", "text/html"),), b"<html>ok</html>"),
            MockRoute("GET", "app.test", "/api/bad", 500, (("Content-Type", "text/html"),),
                      b"You have an error in your SQL syntax near '1'"),
        ])
        base = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/ok", label="sqli"))
        probe = ws.probe.run(ProbeRequest(action_id="2", url="http://app.test/api/bad", label="sqli"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "sqli",
                                {base.evidence_id: "baseline", probe.evidence_id: "probe"})
        v = ErrorSignatureMatch().run(obs, ErrorSignatureMatch.Args())
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.85)

    def test_error_signature_negative_same_error(self):
        ws = self.make_ws([
            MockRoute("GET", "app.test", "/e1", 500, (("Content-Type", "text/html"),),
                      b"ORA-00933: SQL command not properly ended"),
            MockRoute("GET", "app.test", "/e2", 500, (("Content-Type", "text/html"),),
                      b"ORA-00933: SQL command not properly ended"),
        ])
        base = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/e1", label="o"))
        probe = ws.probe.run(ProbeRequest(action_id="2", url="http://app.test/e2", label="o"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "o",
                                {base.evidence_id: "baseline", probe.evidence_id: "probe"})
        v = ErrorSignatureMatch().run(obs, ErrorSignatureMatch.Args())
        self.assertFalse(v.passed)

    def test_file_signature_positive_git(self):
        ws = self.make_ws([
            MockRoute("GET", "app.test", "/.git/HEAD", 200, (("Content-Type", "text/plain"),),
                      b"ref: refs/heads/main\n"),
        ])
        r = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/.git/HEAD",
                                      label="leak", payload_class="wellknown_path"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "leak", {r.evidence_id: "probe"})
        v = FileSignatureMatch().run(obs, FileSignatureMatch.Args())
        self.assertTrue(v.passed, v.rationale)
        self.assertGreaterEqual(v.confidence, 0.85)

    def test_file_signature_negative_spa(self):
        ws = self.make_ws([
            MockRoute("GET", "app.test", "/.git/HEAD", 200, (("Content-Type", "text/html"),),
                      b"<!doctype html><html><body><div id=\"root\"></div></body></html>"),
        ])
        r = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/.git/HEAD",
                                      label="leak2", payload_class="wellknown_path"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "leak2", {r.evidence_id: "probe"})
        v = FileSignatureMatch().run(obs, FileSignatureMatch.Args())
        self.assertFalse(v.passed, v.rationale)

    def test_file_signature_confirms_stack_trace_inside_json(self):
        # 真实靶场上抓到的：500 的 application/json 里带着完整 Java 堆栈。
        # 只看 content-type 会当成「普通 JSON 接口」扣分，实际是把内部结构告诉了调用方。
        body = (b'{\n  "timestamp": "2026-11-12T04:57:06.578+00:00",\n  "status": 500,\n'
                b'  "error": "Internal Server Error",\n'
                b'  "trace": "java.lang.NullPointerException: Cannot invoke ..."\n}')
        ws = self.make_ws([
            MockRoute("GET", "app.test", "/api/boom", 500,
                      (("Content-Type", "application/json"),), body),
        ])
        r = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/boom",
                                      label="leak3", payload_class="wellknown_path"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "leak3", {r.evidence_id: "probe"})
        v = FileSignatureMatch().run(obs, FileSignatureMatch.Args())
        self.assertTrue(v.passed, v.rationale)
        self.assertIn("stack_trace", v.metrics["hits"])
        self.assertNotIn("json_api", v.metrics["neg"])

    def test_file_signature_plain_json_still_refutes(self):
        # 反面对照：同样是 JSON、同样以 { 开头，但没有堆栈，就还是「一个接口」不是泄露。
        ws = self.make_ws([
            MockRoute("GET", "app.test", "/api/ok", 200,
                      (("Content-Type", "application/json"),), b'{"id": 1, "name": "x"}'),
        ])
        r = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/ok",
                                      label="leak4", payload_class="wellknown_path"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "leak4", {r.evidence_id: "probe"})
        v = FileSignatureMatch().run(obs, FileSignatureMatch.Args())
        self.assertFalse(v.passed, v.rationale)
        self.assertIn("json_api", v.metrics["neg"])

    def test_unknown_oracle_args_rejected(self):
        with self.assertRaises(TypeError):
            build_oracle("differential_object_access", {"nope": 1})

    def test_file_signature_names_what_actually_hit(self):
        # 模板标题是「敏感构建产物/凭据文件暴露」，命中的却是堆栈。标题必须跟着命中走，
        # 否则用户拿着一份 500 堆栈当「凭据泄露」去处置。
        body = (b'{\n  "status": 500,\n'
                b'  "trace": "java.lang.NullPointerException: Cannot invoke \\"x\\"\\n'
                b'\\tat com.example.Foo.bar(Foo.java:42)"\n}')
        ws = self.make_ws([
            MockRoute("GET", "app.test", "/api/boom", 500,
                      (("Content-Type", "application/json"),), body),
        ])
        r = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/boom",
                                      label="leak5", payload_class="wellknown_path"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "leak5", {r.evidence_id: "probe"})
        v = FileSignatureMatch().run(obs, FileSignatureMatch.Args())
        self.assertTrue(v.passed, v.rationale)
        self.assertIn("堆栈", v.title)
        self.assertIn("title", v.to_json())

    def test_refuted_file_signature_carries_no_title(self):
        # 没确认就不该改标题：否则「已否定」的结论还会显示成一个唬人的名字。
        ws = self.make_ws([
            MockRoute("GET", "app.test", "/api/ok2", 200,
                      (("Content-Type", "application/json"),), b'{"id": 1}'),
        ])
        r = ws.probe.run(ProbeRequest(action_id="1", url="http://app.test/api/ok2",
                                      label="leak6", payload_class="wellknown_path"))
        obs = load_observations(ws.store, ws.cas, "ENG-T", "leak6", {r.evidence_id: "probe"})
        v = FileSignatureMatch().run(obs, FileSignatureMatch.Args())
        self.assertFalse(v.passed)
        self.assertEqual(v.title, "")
        self.assertNotIn("title", v.to_json())


class VhxTest(unittest.TestCase):
    def test_builtin_templates_lint(self):
        from pta import vhx
        for raw in vhx.TEMPLATES:
            t = vhx.load(raw)
            self.assertEqual(t.raw["vhx_version"], "1.0")

    def test_bad_oracle_rejected(self):
        import copy
        from pta import vhx
        from pta.errors import VhxInvalid
        bad = copy.deepcopy(vhx.TEMPLATES[0])
        bad["oracle"] = {"name": "not_registered"}
        with self.assertRaises(VhxInvalid):
            vhx.load(bad)

    def test_l2_without_approval_rejected(self):
        import copy
        from pta import vhx
        from pta.errors import VhxInvalid
        bad = copy.deepcopy(vhx.TEMPLATES[0])
        bad["side_effect_level"] = "L2"
        bad["requires_approval"] = False
        with self.assertRaises(VhxInvalid):
            vhx.load(bad)


if __name__ == "__main__":
    unittest.main()
