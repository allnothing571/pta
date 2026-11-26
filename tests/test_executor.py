"""P1 执行闭环测试：模板 → 动作 → 探针 → oracle → finding。"""
import copy
import json
import unittest

from pta import vhx
from pta.executor import Executor, Target, finding_id
from pta.transport import MockRoute
from support import WorkspaceCase

OBJ = b'{"id":7,"email":"alice@corp.test","role":"user"}'


def routes():
    return [
        MockRoute("GET", "shop.test", "/rest/user/7", 200, (("Content-Type", "application/json"),),
                  OBJ, identity="Bearer A"),
        MockRoute("GET", "shop.test", "/rest/user/7", 200, (("Content-Type", "application/json"),),
                  OBJ, identity="Bearer B"),
        MockRoute("GET", "shop.test", "/api/search", 200, (("Content-Type", "text/html"),),
                  b"<html>results</html>"),
        MockRoute("GET", "shop.test", "/.git/HEAD", 200, (("Content-Type", "text/plain"),),
                  b"ref: refs/heads/main\n"),
        MockRoute("GET", "shop.test", "/.env", 200, (("Content-Type", "text/html"),),
                  b"<!doctype html><html><div id=\"root\"></div></html>"),
    ]


def tpl(tid):
    for t in vhx.TEMPLATES:
        if t["id"] == tid:
            return vhx.load(copy.deepcopy(t))
    raise KeyError(tid)


class ExecutorTest(WorkspaceCase):
    def ws(self):
        ws = self.make_ws(routes(), domains=("shop.test",))
        ws.vault.put("cred/A/authorization", "Bearer A")
        ws.vault.put("cred/B/authorization", "Bearer B")
        return ws

    def test_idor_confirmed_and_persisted(self):
        ws = self.ws()
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("idor-object-ref"),
            Target(url="http://shop.test/rest/user/7", identity_baseline="A", identity_probe="B"),
        )
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.85)
        # baseline + probe + decoy（不存在的对象 404，负对照没有触发降级）
        self.assertEqual(len(f.evidence_ids), 3)
        self.assertEqual(f.verdict["metrics"].get("decoy_status"), 404)
        self.assertLessEqual(f.requests_used, 12)
        rows = ws.store.list_findings("ENG-T")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "confirmed")
        self.assertEqual(f.id, finding_id("idor-object-ref", f.evidence_ids))
        logged = [r for r in ws.store.logs("ENG-T") if r["decision"] == "finding"]
        self.assertEqual(len(logged), 1)

    def test_idor_refuted_when_same_identity(self):
        ws = self.ws()
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("idor-object-ref"),
            Target(url="http://shop.test/rest/user/7", identity_baseline="A", identity_probe="A"),
        )
        self.assertEqual(f.status, "refuted")
        self.assertLess(f.confidence, 0.60)

    def test_id_shift_derived_from_query(self):
        """id_plus_one 缺失时从 ?id=7 自动推 8（供显式声明 id_shift 的模板用）。"""
        ex = Executor(self.ws().probe, None, "ENG-T")
        self.assertEqual(ex._derive_id_plus_one(Target(
            url="http://shop.test/rest/user/7?id=7", param_path="query:id")), "8")
        self.assertEqual(ex._derive_id_plus_one(Target(
            url="http://shop.test/rest/user/7")), "8")

    def test_id_shift_skipped_without_integer(self):
        ex = Executor(self.ws().probe, None, "ENG-T")
        self.assertIsNone(ex._derive_id_plus_one(Target(
            url="http://shop.test/rest/user/alice", identity_baseline="A")))
        self.assertIsNone(ex._derive_id_plus_one(Target(
            url="http://shop.test/rest/user/alice?name=alice", param_path="query:name")))

    def test_info_disclosure_confirmed(self):
        ws = self.ws()
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("info-disclosure-artifact"), Target(url="http://shop.test/.git/HEAD"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertEqual(len(f.evidence_ids), 1)

    def test_info_disclosure_refuted_on_spa(self):
        ws = self.ws()
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("info-disclosure-artifact"), Target(url="http://shop.test/.env"))
        self.assertEqual(f.status, "refuted", f.verdict)

    def test_sqli_refuted_without_error_signature(self):
        ws = self.ws()
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("sqli-error-boolean"),
            Target(url="http://shop.test/api/search", param_path="query:q",
                   identity_baseline="A", identity_probe="A"),
        )
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertLessEqual(f.requests_used, 15)

    def test_budget_is_hard_cap(self):
        ws = self.ws()
        t = tpl("sqli-error-boolean")
        t.raw["budget"]["max_requests"] = 3
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            t, Target(url="http://shop.test/api/search", param_path="query:q",
                      identity_baseline="A", identity_probe="A"))
        self.assertLessEqual(f.requests_used, 3)
        self.assertEqual(f.stop_reason, "budget_exhausted")

    def test_unsupported_action_rejected(self):
        from pta.errors import VhxInvalid
        ws = self.ws()
        t = tpl("idor-object-ref")
        t.raw["probe"]["sequence"] = ["http_request", "browser_nav"]
        with self.assertRaises(VhxInvalid):
            Executor(ws.probe, ws.store, "ENG-T").run(
                t, Target(url="http://shop.test/rest/user/7",
                          identity_baseline="A", identity_probe="B"))

    def test_pending_approval_stops_run(self):
        ws = self.ws()
        ws.probe.oob_host = "oob.test"
        t = tpl("sqli-error-boolean")
        t.raw["mutator_hints"] = [{"payload_class": "oob_url"}]
        t.raw["side_effect_level"] = "L2"
        t.raw["requires_approval"] = True
        f = Executor(ws.probe, ws.store, "ENG-T").run(
            t, Target(url="http://shop.test/api/search", param_path="query:q",
                      identity_baseline="A", identity_probe="A"))
        self.assertTrue(f.stop_reason.startswith("pending_approval"), f.stop_reason)
        state_findings = ws.store.list_findings("ENG-T")
        self.assertEqual(len(state_findings), 1)

    def test_sse_emits_finding(self):
        ws = self.ws()
        q = ws.bus.subscribe()
        Executor(ws.probe, ws.store, "ENG-T").run(
            tpl("info-disclosure-artifact"), Target(url="http://shop.test/.git/HEAD"))
        ev = q.get(timeout=2)
        self.assertEqual(ev["type"], "finding")
        self.assertEqual(ev["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
