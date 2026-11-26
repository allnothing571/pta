"""Critic：一票否决、只读证据、不发请求。"""
import copy
import json
import unittest

from pta import vhx
from pta.critic import Critic
from pta.executor import Executor, Target
from pta.llm import ScriptedClient
from pta.planner import EngagementRunner, Planner
from pta.transport import MockRoute
from support import WorkspaceCase, idor_routes

TPL = "idor-object-ref"


def idor_tpl():
    raw = [t for t in vhx.TEMPLATES if t["id"] == TPL][0]
    return vhx.load(copy.deepcopy(raw))


class Base(WorkspaceCase):
    def ws(self):
        routes = idor_routes() + [MockRoute("GET", "app.test", "/api/other", 200, (), b'{"ok":1}')]
        ws = self.make_ws(routes, domains=("app.test",))
        ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
        ws.vault.put("cred/B/authorization", "Bearer TOKEN-B")
        return ws

    def run_idor(self, ws, probe="B"):
        return Executor(ws.probe, ws.store, "ENG-T").run(
            idor_tpl(),
            Target(url="http://app.test/api/users/1",
                   identity_baseline="A", identity_probe=probe))

    def confirmed(self, ws):
        f = self.run_idor(ws)
        self.assertEqual(f.status, "confirmed", f.verdict)
        return f

    def manual(self, ws, **over):
        f = self.confirmed(ws)
        rec = {"id": over.get("id", f.id), "engagement_id": "ENG-T",
               "template_id": over.get("template_id", TPL),
               "title": over.get("title", "手工 finding"),
               "status": over.get("status", f.status),
               "confidence": over.get("confidence", f.confidence),
               "evidence_ids": over.get("evidence_ids", f.evidence_ids),
               "verdict": over.get("verdict", f.verdict),
               "created_at": "2026-11-09T00:00:00Z"}
        ws.store.put_finding(rec)
        return rec

    def fake_confirmed(self, ws, fid, evidence_ids, confidence=0.9, verdict=None):
        """直接写一条 confirmed，用来单独测试某条规则。"""
        rec = {"id": fid, "engagement_id": "ENG-T", "template_id": TPL,
               "title": "假 finding", "status": "confirmed", "confidence": confidence,
               "evidence_ids": list(evidence_ids),
               "verdict": verdict or {"metrics": {}, "rationale": "test"},
               "created_at": "2026-11-09T00:00:00Z"}
        ws.store.put_finding(rec)
        return rec

    def probe_other(self, ws, label="other"):
        from pta.probe import ProbeRequest
        return ws.probe.run(ProbeRequest(action_id="o", url="http://app.test/api/other",
                                         identity="A", label=label))

    def row(self, ws, fid):
        for r in ws.store.list_findings("ENG-T"):
            if r["id"] == fid:
                return r
        raise KeyError(fid)


class PassTest(Base):
    def test_clean_confirmed_is_kept(self):
        ws = self.ws()
        f = self.confirmed(ws)
        crit = Critic(ws).review_finding(f)
        self.assertEqual(crit.status, "kept", crit.to_json())
        self.assertEqual(self.row(ws, f.id)["status"], "confirmed")

    def test_critic_never_sends(self):
        ws = self.ws()
        f = self.confirmed(ws)
        sent, used = len(ws.transport.sent), ws.budget.used
        Critic(ws).review_finding(f)
        self.assertEqual(len(ws.transport.sent), sent)
        self.assertEqual(ws.budget.used, used)


class VetoTest(Base):
    def test_tampered_evidence_vetoes(self):
        ws = self.ws()
        f = self.confirmed(ws)
        row = ws.store.get_evidence_row(f.evidence_ids[0])
        blob = ws.cas.get(row["body_sha256"])
        path = ws.cas.path_for(row["body_sha256"])
        with open(path, "wb") as fh:          # 直接改盘上密文，模拟证据被篡改
            fh.write(ws.cas.cipher.encrypt(b"tampered"))
        try:
            crit = Critic(ws).review_finding(f)
            self.assertEqual(crit.status, "vetoed", crit.to_json())
            self.assertIn("evidence_corrupted", [b.code for b in crit.blocks])
            self.assertEqual(self.row(ws, f.id)["status"], "refuted")
            self.assertEqual(self.row(ws, f.id)["overridden_by"], "critic")
            saved = json.loads(self.row(ws, f.id)["verdict_json"])
            self.assertEqual(saved["critique"]["status"], "vetoed")
        finally:
            with open(path, "wb") as fh:
                fh.write(ws.cas.cipher.encrypt(blob))

    def test_single_evidence_pairing_oracle_vetoed(self):
        ws = self.ws()
        f = self.confirmed(ws)
        rec = self.manual(ws, evidence_ids=[f.evidence_ids[0]], id="one-ev")
        crit = Critic(ws).review_row(self.row(ws, rec["id"]))
        self.assertIn("counter_evidence_missing", [b.code for b in crit.blocks])

    def test_same_identity_vetoed(self):
        ws = self.ws()
        f = self.run_idor(ws, probe="A")            # oracle 已判 refuted
        self.assertEqual(f.status, "refuted")
        # 假设有人把它手工改成 confirmed：Critic 必须拦下来
        self.fake_confirmed(ws, "same-id", f.evidence_ids)
        crit = Critic(ws).review_row(self.row(ws, "same-id"))
        self.assertEqual(crit.status, "vetoed")
        self.assertIn("same_identity", [b.code for b in crit.blocks])

    def test_confidence_mismatch_vetoed(self):
        ws = self.ws()
        self.manual(ws, confidence=0.5, id="low-conf")
        crit = Critic(ws).review_row(self.row(ws, "low-conf"))
        self.assertIn("confidence_status_mismatch", [b.code for b in crit.blocks])

    def test_missing_evidence_vetoed(self):
        ws = self.ws()
        self.manual(ws, evidence_ids=["deadbeef"], id="missing-ev")
        crit = Critic(ws).review_row(self.row(ws, "missing-ev"))
        self.assertIn("evidence_missing", [b.code for b in crit.blocks])

    def test_unknown_template_vetoed(self):
        ws = self.ws()
        self.manual(ws, template_id="nope", id="bad-tpl")
        crit = Critic(ws).review_row(self.row(ws, "bad-tpl"))
        self.assertEqual(crit.blocks[0].code, "template_unknown")

    def test_out_of_scope_evidence_vetoed(self):
        ws = self.ws()
        f = self.confirmed(ws)
        ws.store.conn.execute("UPDATE evidence SET host=? WHERE evidence_id=?",
                              ("evil.test", f.evidence_ids[0]))
        ws.store.conn.commit()
        crit = Critic(ws).review_finding(f)
        self.assertIn("evidence_out_of_scope", [b.code for b in crit.blocks])

    def test_model_veto(self):
        ws = self.ws()
        f = self.confirmed(ws)
        model = ScriptedClient([json.dumps(
            {"decision": "reject", "reasons": ["疑似登录跳转，不能证明越权"]},
            ensure_ascii=False)])
        crit = Critic(ws, model=model).review_finding(f)
        self.assertEqual(crit.status, "vetoed")
        self.assertIn("model_veto", [b.code for b in crit.blocks])
        self.assertEqual(self.row(ws, f.id)["status"], "refuted")

    def test_model_cannot_promote(self):
        ws = self.ws()
        f = self.run_idor(ws, probe="A")
        self.assertEqual(f.status, "refuted")
        model = ScriptedClient([json.dumps({"decision": "accept", "reasons": ["像"]})])
        crit = Critic(ws, model=model).review_finding(f)
        self.assertEqual(crit.status, "kept")
        self.assertEqual(self.row(ws, f.id)["status"], "refuted")

    def test_model_refusal_is_warning_not_veto(self):
        ws = self.ws()
        f = self.confirmed(ws)
        crit = Critic(ws, model=ScriptedClient(["I can't help with that."])).review_finding(f)
        self.assertEqual(crit.status, "warned")
        self.assertIn("critic_model_unavailable", [w.code for w in crit.warnings])
        self.assertEqual(self.row(ws, f.id)["status"], "confirmed")


class WarnTest(Base):
    def test_duplicate_is_warning_only(self):
        ws = self.ws()
        f = self.confirmed(ws)
        other = self.probe_other(ws)                 # 另一条证据，避免 finding_id 相同
        self.fake_confirmed(ws, "dup1", [other.evidence_id])
        crit = Critic(ws).review_finding(f)
        self.assertEqual(crit.status, "warned", crit.to_json())
        self.assertIn("duplicate_finding", [w.code for w in crit.warnings])
        self.assertEqual(self.row(ws, f.id)["status"], "confirmed")

    def test_skipped_payload_warns(self):
        ws = self.ws()
        f = self.confirmed(ws)
        ver = dict(f.verdict, skipped=["id_shift:目标 URL 无整数参数"])
        self.manual(ws, verdict=ver, id="skip1")
        crit = Critic(ws).review_row(self.row(ws, "skip1"))
        self.assertIn("payload_skipped", [w.code for w in crit.warnings])


class SameIdentityExemptTest(Base):
    """JWT 的两条证据故意同身份，不能被 same_identity 误杀。"""

    def test_jwt_finding_kept(self):
        from pta import jwtlab
        from test_jwt import BODY, GOOD
        forged = jwtlab.forge(GOOD, "none")
        routes = [
            MockRoute("GET", "app.test", "/api/me", 200,
                      (("Content-Type", "application/json"),), BODY, identity=GOOD),
            MockRoute("GET", "app.test", "/api/me", 200,
                      (("Content-Type", "application/json"),), BODY, identity=forged),
        ]
        ws = self.make_ws(routes, domains=("app.test",))
        ws.vault.put("cred/A/authorization", GOOD)
        from pta.executor import Executor as Ex
        tpl = vhx.load(copy.deepcopy(
            [t for t in vhx.TEMPLATES if t["id"] == "jwt-trust-boundary"][0]))
        f = Ex(ws.probe, ws.store, "ENG-T").run(
            tpl, Target(url="http://app.test/api/me", identity_baseline="A",
                        identity_probe="A", param_path="header:authorization"))
        self.assertEqual(f.status, "confirmed", f.verdict)
        crit = Critic(ws).review_finding(f)
        self.assertEqual(crit.status, "kept", crit.to_json())
        self.assertNotIn("same_identity", [b.code for b in crit.blocks])


class RunnerIntegrationTest(Base):
    def test_runner_runs_critic_and_reports(self):
        ws = self.ws()
        good = json.dumps({"candidates": [{"template_id": TPL,
                                           "url": "http://app.test/api/users/1",
                                           "identity_baseline": "A",
                                           "identity_probe": "B"}]}, ensure_ascii=False)
        runner = EngagementRunner(ws, Planner(ws, model=ScriptedClient([good] * 3)),
                                  max_rounds=1, critic=Critic(ws))
        out = runner.run()
        self.assertIn("confirmed", out["counts"], out)
        self.assertEqual(len(out["critiques"]), 1)
        self.assertEqual(out["critiques"][0]["status"] in ("kept", "warned"), True)


if __name__ == "__main__":
    unittest.main()
