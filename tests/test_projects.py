"""多项目壳：阶段判定、台账、筛选、交付、后台任务。

这一层的规则都是纯函数（除 facts/listing 读库之外），所以测试分两类：
- 不碰磁盘：手工造一份 facts，验 stage_of / why_stopped / steps_of / next_actions
- 碰磁盘：真建工作区（sqlite + vault），验台账与筛选口径
"""
import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from pta import projects as proj
from pta import targets
from pta.events import Bus
from pta.probe import ProbeRequest
from pta.scope import Scope
from pta.transport import MockRoute, MockTransport
from pta.workspace import init_workspace, open_workspace
from support import fake_dns


def facts_for(**kw):
    """一份「都做完了」的 facts，按需覆盖某几项。"""
    base = {
        "exists": True,
        "identities": ["A"],
        "evidence": 3,
        "recon_pages": 1,
        "pending": 0,
        "candidates": 5,
        "findings": {"total": 1, "confirmed": 1, "hypothesis": 0, "refuted": 0},
    }
    base.update(kw)
    return base


def finding(fid, status, confidence=0.9):
    return {
        "id": fid,
        "engagement_id": "",
        "template_id": "idor-object-ref",
        "title": "t",
        "status": status,
        "confidence": confidence,
        "evidence_ids": [],
        "verdict": {"metrics": {}, "rationale": "r"},
        "created_at": "2026-11-13T00:00:00Z",
    }


class StageTest(unittest.TestCase):
    def test_missing_beats_everything_else(self):
        f = facts_for(exists=False, error="目录不在了", delivered_at="2026-11-13T00:00:00Z")
        self.assertEqual(proj.stage_of(f), "missing")
        self.assertEqual(proj.why_stopped(f), "目录不在了")

    def test_delivered_beats_in_flight(self):
        f = facts_for(delivered_at="2026-11-13T00:00:00Z", delivered_by="me")
        self.assertEqual(proj.stage_of(f), "delivered")
        self.assertIn("已经交付", proj.why_stopped(f))
        self.assertIn("me", proj.why_stopped(f))

    def test_no_identity_comes_before_no_recon(self):
        self.assertEqual(proj.stage_of(facts_for(identities=[], evidence=0)), "no_identity")

    def test_no_recon_when_no_evidence(self):
        self.assertEqual(proj.stage_of(facts_for(evidence=0)), "no_recon")

    def test_no_verdict_when_evidence_but_no_findings(self):
        f = facts_for(findings={"total": 0, "confirmed": 0, "hypothesis": 0, "refuted": 0})
        self.assertEqual(proj.stage_of(f), "no_verdict")

    def test_no_verdict_says_whether_discover_ran(self):
        f = facts_for(candidates=None,
                      findings={"total": 0, "confirmed": 0, "hypothesis": 0, "refuted": 0})
        self.assertIn("还没跑过 discover", proj.why_stopped(f))
        f = facts_for(candidates=7,
                      findings={"total": 0, "confirmed": 0, "hypothesis": 0, "refuted": 0})
        self.assertIn("7 个候选", proj.why_stopped(f))

    def test_hypothesis_needs_review(self):
        f = facts_for(findings={"total": 3, "confirmed": 1, "hypothesis": 2, "refuted": 0})
        self.assertEqual(proj.stage_of(f), "review")
        self.assertIn("2 条 hypothesis", proj.why_stopped(f))

    def test_pending_approval_needs_review(self):
        f = facts_for(pending=2)
        self.assertEqual(proj.stage_of(f), "review")
        self.assertIn("2 条 L2", proj.why_stopped(f))

    def test_review_lists_both_reasons(self):
        f = facts_for(pending=1,
                      findings={"total": 2, "confirmed": 0, "hypothesis": 1, "refuted": 1})
        why = proj.why_stopped(f)
        self.assertIn("1 条 hypothesis", why)
        self.assertIn("1 条 L2", why)

    def test_all_refuted_is_not_deliverable(self):
        f = facts_for(findings={"total": 2, "confirmed": 0, "hypothesis": 0, "refuted": 2})
        self.assertEqual(proj.stage_of(f), "no_confirmed")
        self.assertFalse(proj.is_deliverable(f))
        self.assertIn("2 条结论全是否定", proj.why_stopped(f))

    def test_one_confirmed_and_clean_is_deliverable(self):
        f = facts_for()
        self.assertEqual(proj.stage_of(f), "deliverable")
        self.assertTrue(proj.is_deliverable(f))
        self.assertIn("1 条 confirmed", proj.why_stopped(f))


class StepsTest(unittest.TestCase):
    def test_exactly_one_current(self):
        f = facts_for(identities=[], evidence=0,
                      findings={"total": 0, "confirmed": 0, "hypothesis": 0, "refuted": 0})
        steps = proj.steps_of(f)
        self.assertEqual([s["id"] for s in steps],
                         ["workspace", "identity", "recon", "verdict", "review", "deliver"])
        states = [s["state"] for s in steps]
        self.assertEqual(states.count("current"), 1)
        self.assertEqual(states[0], "done")          # 目录在
        self.assertEqual(states[1], "current")       # 缺身份
        self.assertEqual(states[2], "todo")

    def test_delivered_marks_every_step_done(self):
        steps = proj.steps_of(facts_for(delivered_at="2026-11-13T00:00:00Z"))
        self.assertEqual([s["state"] for s in steps], ["done"] * 6)

    def test_missing_workspace_has_no_current(self):
        steps = proj.steps_of(facts_for(exists=False))
        self.assertEqual([s["state"] for s in steps], ["todo"] * 6)

    def test_recon_detail_counts_pages(self):
        f = facts_for(evidence=9, recon_pages=4)
        detail = [s for s in proj.steps_of(f) if s["id"] == "recon"][0]["detail"]
        self.assertIn("9 条证据", detail)
        self.assertIn("4 页侦察", detail)


class NextActionsTest(unittest.TestCase):
    def test_deliverable_offers_deliver_and_report(self):
        kinds = [a["kind"] for a in proj.next_actions(facts_for())]
        self.assertEqual(kinds, ["deliver", "report"])

    def test_missing_offers_nothing(self):
        self.assertEqual(proj.next_actions(facts_for(exists=False)), [])

    def test_no_identity_offers_identity_only(self):
        kinds = [a["kind"] for a in proj.next_actions(facts_for(identities=[]))]
        self.assertEqual(kinds, ["identity"])

    def test_review_points_at_review(self):
        f = facts_for(findings={"total": 2, "confirmed": 0, "hypothesis": 2, "refuted": 0})
        self.assertEqual(proj.next_actions(f)[0]["kind"], "review")


class LedgerCase(unittest.TestCase):
    """每个测试一个独立的 PTA_HOME，绝不碰用户真台账。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pta-proj-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._old_home = os.environ.get("PTA_HOME")
        os.environ["PTA_HOME"] = os.path.join(self.tmp, "home")
        self.addCleanup(self._restore_home)
        self._workspaces = []

    def _restore_home(self):
        if self._old_home is None:
            os.environ.pop("PTA_HOME", None)
        else:
            os.environ["PTA_HOME"] = self._old_home
        for ws in self._workspaces:
            try:
                ws.store.close()
            except Exception:
                pass

    def mk(self, name, identities=("A",), findings=(), evidence=1, recon=0, parent="labs"):
        """真建一个工作区并登记台账：evidence 条证据由真的 probe 产生。"""
        root = os.path.join(self.tmp, parent, name)
        scope = Scope(engagement_id="ENG-" + name.upper(), domains=("app.test",),
                      allow_private=True, rate_per_host=1000.0, max_requests=5000,
                      allowed_ports=(80, 443, 8080))
        init_workspace(root, scope)
        routes = [MockRoute("GET", "app.test", "/probe", 200,
                            (("Content-Type", "text/plain"),), b"ok")]
        ws = open_workspace(root, transport=MockTransport(routes), dns=fake_dns())
        self._workspaces.append(ws)
        for ident in identities:
            ws.vault.put("cred/%s/authorization" % ident, "Bearer TOKEN-" + ident)
        for i in range(evidence):
            # 每条都要有自己的 URL：evidence_id 由 canonical request + body 算，
            # 同一个 URL 打两次会被 upsert 成一条（这是设计，不是 bug）
            ws.probe.run(ProbeRequest(action_id="e%d" % i, url="http://app.test/probe?e=%d" % i,
                                      identity=(identities or ["none"])[0], label="probe"))
        for i in range(recon):
            ws.probe.run(ProbeRequest(action_id="r%d" % i, url="http://app.test/probe?r=%d" % i,
                                      identity=(identities or ["none"])[0], label="recon"))
        for f in findings:
            rec = dict(f)
            rec["engagement_id"] = scope.engagement_id
            ws.store.put_finding(rec)
        targets.register(root, engagement_id=scope.engagement_id, domains=("app.test",),
                         alias=name, name=name)
        return root


class FactsTest(LedgerCase):
    def test_facts_reads_identity_findings_and_evidence(self):
        root = self.mk("alpha", identities=("A", "B"),
                       findings=[finding("f1", "confirmed"), finding("f2", "refuted")],
                       evidence=2, recon=1)
        f = proj.facts(root)
        self.assertEqual(sorted(f["identities"]), ["A", "B"])
        self.assertEqual(f["evidence"], 3)
        self.assertEqual(f["recon_pages"], 1)
        self.assertEqual(f["findings"]["total"], 2)
        self.assertEqual(f["findings"]["confirmed"], 1)
        self.assertEqual(f["findings"]["refuted"], 1)
        self.assertTrue(f["last_activity"])
        self.assertEqual(proj.stage_of(f), "deliverable")

    def test_missing_directory_is_reported_not_raised(self):
        f = proj.facts(os.path.join(self.tmp, "nope"))
        self.assertFalse(f["exists"])
        self.assertEqual(proj.stage_of(f), "missing")

    def test_broken_scope_is_reported(self):
        root = os.path.join(self.tmp, "broken")
        os.makedirs(root)
        with open(os.path.join(root, "scope.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        f = proj.facts(root)
        self.assertIn("scope.json", f["error"])

    def test_candidates_are_none_until_discover_runs(self):
        root = self.mk("nodisc")
        self.assertIsNone(proj.facts(root)["candidates"])

    def test_discover_counts_are_picked_up(self):
        root = self.mk("withdisc")
        with open(os.path.join(root, "discover.json"), "w", encoding="utf-8") as fh:
            json.dump({"counts": {"suggestions": 6, "harvested": 2, "graph_edges": 3}}, fh)
        f = proj.facts(root)
        self.assertEqual(f["candidates"], 6)
        self.assertEqual(f["harvested"], 2)
        self.assertEqual(f["graph_edges"], 3)


class CreateTest(LedgerCase):
    def test_new_workspace_gets_scope_and_ledger_row(self):
        root = os.path.join(self.tmp, "fresh")
        out = proj.create("我的盒子", "http://127.0.0.1:8080/app", root, note="第一轮")
        self.assertTrue(os.path.exists(os.path.join(root, "scope.json")))
        self.assertEqual(out["created"]["root"], root)
        self.assertIn(8080, out["scope"]["allowed_ports"])
        self.assertTrue(out["scope"]["allow_private"])       # 127.0.0.1
        row = targets.get(out["project"]["alias"])
        self.assertIsNotNone(row)
        self.assertEqual(row["name"], "我的盒子")
        self.assertEqual(targets.get(out["created"]["engagement_id"])["name"], "我的盒子")

    def test_public_host_is_not_private(self):
        root = os.path.join(self.tmp, "pub")
        out = proj.create("pub", "https://app.example.com/", root)
        self.assertFalse(out["scope"]["allow_private"])
        self.assertEqual(out["scope"]["allowed_ports"], [80, 443])

    def test_rejects_bad_input(self):
        cases = [
            ("", "http://app.test/", "bad_name"),
            ("x", "ftp://app.test/", "bad_url"),
            ("x", "http://app.test/", "relative/path"),
        ]
        for name, url, ws in cases:
            with self.assertRaises(proj.ProjectError) as ctx:
                proj.create(name, url, ws)
            self.assertTrue(ctx.exception.code.startswith("bad_"), ctx.exception.code)

    def test_adopts_a_workspace_that_already_has_scope(self):
        root = os.path.join(self.tmp, "adopt-me")
        init_workspace(root, Scope(engagement_id="LEGACY", domains=("127.0.0.1",),
                                   allow_private=True, rate_per_host=5.0, max_requests=900,
                                   allowed_ports=(80, 443, 8080)))
        out = proj.create("收编", "http://127.0.0.1:8080/", root)
        self.assertTrue(out["created"]["imported"])
        self.assertEqual(out["created"]["engagement_id"], "LEGACY")   # 不重写别人的边界
        self.assertEqual(targets.get("LEGACY")["name"], "收编")

    def test_second_create_says_which_alias(self):
        root = os.path.join(self.tmp, "twice")
        first = proj.create("twice", "http://app.test/", root)
        with self.assertRaises(proj.ProjectError) as ctx:
            proj.create("twice again", "http://app.test/", root)
        self.assertEqual(ctx.exception.code, "already_exists")
        self.assertEqual(ctx.exception.extra["alias"], first["project"]["alias"])


class ListingTest(LedgerCase):
    def setUp(self):
        super(ListingTest, self).setUp()
        self.a = self.mk("alpha", findings=[finding("f1", "confirmed")], parent="labs")
        self.b = self.mk("beta", identities=(), evidence=0, parent="labs")
        self.c = self.mk("gamma", findings=[finding("f2", "confirmed")], parent="clients")
        proj.deliver("gamma", delivered=True)

    def test_all(self):
        out = proj.listing()
        self.assertEqual(out["total"], 3)
        self.assertEqual(sorted(out["workspaces"]),
                         sorted([os.path.join(self.tmp, "labs"),
                                 os.path.join(self.tmp, "clients")]))

    def test_stage_facet_counts_everything_in_scope(self):
        out = proj.listing(stages=("inflight",))
        self.assertEqual(out["total"], 1)                     # 只有 beta
        facet = {s["id"]: s["count"] for s in out["stages"]}
        self.assertEqual(facet["deliverable"], 1)             # 计数在过滤之前算
        self.assertEqual(facet["delivered"], 1)
        self.assertEqual(facet["no_identity"], 1)
        self.assertEqual([s["id"] for s in out["stages"] if s["inflight"]],
                         ["no_identity", "no_recon", "no_verdict", "review", "no_confirmed"])

    def test_workspace_filter_is_by_parent_directory(self):
        out = proj.listing(workspace=os.path.join(self.tmp, "clients"))
        self.assertEqual([p["alias"] for p in out["projects"]], ["gamma"])

    def test_query_matches_name_and_domain(self):
        self.assertEqual(proj.listing(q="alph")["total"], 1)
        self.assertEqual(proj.listing(q="app.test")["total"], 3)
        self.assertEqual(proj.listing(q="zzz")["total"], 0)

    def test_sorted_by_last_activity(self):
        rows = proj.listing()["projects"]
        stamps = [r["last_activity"] for r in rows]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_summary_shape(self):
        row = proj.summarize(targets.get("alpha"))
        for key in ("alias", "name", "root", "workspace", "stage", "stage_label",
                    "deliverable", "delivered", "counts", "why"):
            self.assertIn(key, row)
        self.assertEqual(row["workspace"], os.path.join(self.tmp, "labs"))
        self.assertEqual(row["counts"]["confirmed"], 1)


class DeliverTest(LedgerCase):
    def test_refuses_until_deliverable(self):
        self.mk("early", identities=(), evidence=0)
        with self.assertRaises(proj.ProjectError) as ctx:
            proj.deliver("early")
        self.assertEqual(ctx.exception.code, "not_deliverable")
        self.assertEqual(ctx.exception.extra["stage"], "no_identity")

    def test_force_delivers_and_notes_it(self):
        self.mk("early2", identities=(), evidence=0)
        out = proj.deliver("early2", force=True, note="客户说先给")
        self.assertTrue(out["delivered"])
        row = targets.get("early2")
        self.assertTrue(row["delivered_at"])
        self.assertIn("强制交付", row["delivered_note"])

    def test_deliver_then_undeliver_moves_the_stage(self):
        self.mk("ready", findings=[finding("f1", "confirmed")])
        self.assertEqual(proj.summarize(targets.get("ready"))["stage"], "deliverable")
        proj.deliver("ready")
        self.assertEqual(proj.summarize(targets.get("ready"))["stage"], "delivered")
        proj.deliver("ready", delivered=False)
        self.assertEqual(proj.summarize(targets.get("ready"))["stage"], "deliverable")

    def test_unknown_alias(self):
        with self.assertRaises(proj.ProjectError) as ctx:
            proj.deliver("nobody")
        self.assertEqual(ctx.exception.code, "not_found")


class DetailTest(LedgerCase):
    def test_detail_has_steps_next_and_why(self):
        self.mk("detail", identities=("A",), evidence=1,
                findings=[finding("f1", "hypothesis", 0.7)])
        d = proj.detail("detail")
        self.assertEqual(d["stage"], "review")
        self.assertEqual([s["id"] for s in d["steps"]][-1], "deliver")
        self.assertEqual(d["next"][0]["kind"], "review")
        self.assertIn("hypothesis", d["why"])
        self.assertEqual(d["project"]["alias"], "detail")

    def test_unknown_alias_404s(self):
        with self.assertRaises(proj.ProjectError) as ctx:
            proj.detail("ghost")
        self.assertEqual(ctx.exception.code, "not_found")


class BookTest(LedgerCase):
    def test_resolve_and_single_mode(self):
        root = self.mk("booked")
        book = proj.ProjectBook()
        self.assertEqual(book.resolve("booked"), root)
        with self.assertRaises(KeyError):
            book.resolve("nope")

        fixed = proj.ProjectBook.single(open_workspace(root, transport=MockTransport([]),
                                                       dns=fake_dns()))
        self.assertEqual(fixed.aliases(), ["booked"])
        self.assertEqual(fixed.default(), "booked")
        self.assertEqual(fixed.resolve(None), root)
        with self.assertRaises(KeyError):
            fixed.resolve("other")

    def test_lru_keeps_only_cache_size(self):
        self.mk("one")
        self.mk("two")
        book = proj.ProjectBook(cache_size=1)
        book.ws("one")
        book.ws("two")
        # 缓存键是 root（同一个目录挂两个别名时不会开出两份 sqlite 句柄）
        self.assertEqual([os.path.basename(k) for k in book._cache.keys()], ["two"])
        book.close_all()
        self.assertEqual(book._cache, {})


class JobTest(LedgerCase):
    def test_runs_in_background_and_reports(self):
        bus = Bus()
        reg = proj.JobRegistry(bus=bus, limit=2)
        q = bus.subscribe()
        gate = threading.Event()

        def work(job):
            job.note("开始")
            gate.wait(3)
            job.note("完了")
            return {"ok": 1}

        job = reg.start("p1", "round", "跑一轮", work)
        self.assertIn(job.state, ("queued", "running"))
        ev = q.get(timeout=3)
        self.assertEqual(ev["type"], "job_started")
        gate.set()
        deadline = time.time() + 5
        while time.time() < deadline and job.state in ("queued", "running"):
            time.sleep(0.02)
        self.assertEqual(job.state, "done")
        self.assertEqual(job.result, {"ok": 1})
        self.assertTrue(any(p.endswith("完了") for p in job.progress), job.progress)
        self.assertLessEqual(len(job.progress), 20)
        ev = q.get(timeout=3)
        self.assertEqual(ev["type"], "job_finished")
        self.assertEqual(ev["project"], "p1")

    def test_one_job_per_project(self):
        reg = proj.JobRegistry(limit=2)
        gate = threading.Event()
        reg.start("busy", "round", "慢的", lambda job: gate.wait(3))
        with self.assertRaises(proj.JobBusy) as ctx:
            reg.start("busy", "recon", "另一个", lambda job: None)
        self.assertEqual(ctx.exception.job.alias, "busy")
        gate.set()

    def test_failure_is_recorded_not_raised(self):
        reg = proj.JobRegistry(limit=1)

        def boom(job):
            raise RuntimeError("炸了")

        job = reg.start("bad", "report", "出报告", boom)
        deadline = time.time() + 5
        while time.time() < deadline and job.state in ("queued", "running"):
            time.sleep(0.02)
        self.assertEqual(job.state, "failed")
        self.assertIn("RuntimeError", job.error)
        self.assertIn("炸了", job.error)

    def test_snapshot_shape(self):
        reg = proj.JobRegistry(limit=1)
        gate = threading.Event()
        reg.start("s1", "round", "跑一轮", lambda job: gate.wait(3))
        rows = reg.snapshot()
        self.assertEqual(rows[0]["alias"], "s1")
        self.assertIn("state", rows[0])
        self.assertIn("progress", rows[0])
        gate.set()


if __name__ == "__main__":
    unittest.main()
