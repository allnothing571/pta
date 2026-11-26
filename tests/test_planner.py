"""Planner：校验、降级、去重、循环编排。"""
import json
import unittest

from pta import vhx
from pta.executor import Executor, Target
from pta.llm import ScriptedClient, looks_like_refusal, validate_schema
from pta.planner import (CANDIDATE_SCHEMA, Candidate, EngagementRunner, Planner,
                         PlannerState, heuristic_candidates)
from pta.probe import ProbeRequest
from support import WorkspaceCase, idor_routes


def plan_json(*candidates, notes=""):
    return json.dumps({"candidates": list(candidates), "notes": notes}, ensure_ascii=False)


IDOR_ROUTE_SEED = "http://app.test/api/users/1"


class Setup(WorkspaceCase):
    def seeded(self, routes=None):
        ws = self.make_ws(routes or idor_routes())
        ws.probe.run(ProbeRequest(action_id="seed", url=IDOR_ROUTE_SEED + "?id=1",
                                  identity="A", label="seed"))
        return ws


class HeuristicTest(Setup):
    def test_proposes_idor_by_param_name(self):
        ws = self.seeded()
        plan = Planner(ws).plan()
        ids = [c.template_id for c in plan.candidates]
        self.assertIn("idor-object-ref", ids)
        self.assertEqual(plan.source, "heuristic")
        self.assertFalse(plan.degraded)

    def test_param_rule_matching(self):
        ws = self.seeded()
        state = PlannerState.collect(ws)
        cands = heuristic_candidates(state)
        idor = [c for c in cands if c.template_id == "idor-object-ref"]
        self.assertTrue(idor)
        self.assertEqual(idor[0].param_path, "query:id")

    def test_no_evidence_means_no_candidates(self):
        ws = self.make_ws(idor_routes())
        plan = Planner(ws).plan()
        self.assertEqual(plan.candidates, [])


class ValidationTest(Setup):
    def test_out_of_scope_rejected(self):
        ws = self.seeded()
        model = ScriptedClient([plan_json(
            {"template_id": "idor-object-ref", "url": "https://evil.test/api", "param_path": "query:id"},
            {"template_id": "idor-object-ref", "url": IDOR_ROUTE_SEED, "param_path": "query:id"},
        )])
        plan = Planner(ws, model=model).plan()
        self.assertEqual(len(plan.candidates), 1)
        reasons = [r["reason"] for r in plan.rejected]
        self.assertTrue(any(r.startswith("out_of_scope") for r in reasons), reasons)

    def test_unknown_template_rejected(self):
        ws = self.seeded()
        model = ScriptedClient([plan_json(
            {"template_id": "made-up-template", "url": IDOR_ROUTE_SEED})])
        plan = Planner(ws, model=model).plan()
        self.assertEqual(plan.candidates, [])
        self.assertEqual(plan.rejected[0]["reason"], "unknown_template")

    def test_bad_param_location_rejected(self):
        ws = self.seeded()
        model = ScriptedClient([plan_json(
            {"template_id": "idor-object-ref", "url": IDOR_ROUTE_SEED, "param_path": "id"})])
        plan = Planner(ws, model=model).plan()
        self.assertEqual(plan.rejected[0]["reason"], "param_path 缺少 location 前缀")

    def test_duplicate_candidates_collapsed(self):
        ws = self.seeded()
        one = {"template_id": "idor-object-ref", "url": IDOR_ROUTE_SEED, "param_path": "query:id"}
        model = ScriptedClient([plan_json(one, dict(one, priority=0.9))])
        plan = Planner(ws, model=model).plan()
        self.assertEqual(len(plan.candidates), 1)
        self.assertEqual(plan.rejected[0]["reason"], "duplicate")

    def test_planner_never_sends_requests(self):
        ws = self.seeded()
        sent_before = len(ws.transport.sent)
        used_before = ws.budget.used
        Planner(ws).plan()
        self.assertEqual(len(ws.transport.sent), sent_before)
        self.assertEqual(ws.budget.used, used_before)

    def test_candidates_sorted_by_priority(self):
        ws = self.seeded()
        model = ScriptedClient([plan_json(
            {"template_id": "info-disclosure-artifact", "url": IDOR_ROUTE_SEED, "priority": 0.2},
            {"template_id": "idor-object-ref", "url": IDOR_ROUTE_SEED,
             "param_path": "query:id", "priority": 0.9},
        )])
        plan = Planner(ws, model=model).plan()
        self.assertEqual(plan.candidates[0].template_id, "idor-object-ref")


class GuardTest(Setup):
    def test_refusal_degrades_to_heuristic(self):
        ws = self.seeded()
        model = ScriptedClient(["I can't help with that.", "I cannot assist."])
        plan = Planner(ws, model=model).plan()
        self.assertTrue(plan.degraded)
        self.assertEqual(plan.source, "heuristic")
        self.assertIn("降级", plan.notes)
        self.assertTrue(plan.candidates)

    def test_schema_retry_then_success(self):
        ws = self.seeded()
        bad = json.dumps({"candidates": [{"template_id": "idor-object-ref"}]})  # 缺 url
        good = plan_json({"template_id": "idor-object-ref", "url": IDOR_ROUTE_SEED,
                          "param_path": "query:id"})
        plan = Planner(ws, model=ScriptedClient([bad, good])).plan()
        self.assertEqual(plan.source, "model")
        self.assertEqual(len(plan.candidates), 1)

    def test_model_unavailable_degrades(self):
        ws = self.seeded()
        plan = Planner(ws, model=ScriptedClient([])).plan()
        self.assertTrue(plan.degraded)
        self.assertEqual(plan.source, "heuristic")

    def test_refusal_detector(self):
        self.assertTrue(looks_like_refusal("I'm sorry, but I can't assist with that."))
        self.assertTrue(looks_like_refusal("抱歉，我无法协助。"))
        self.assertFalse(looks_like_refusal('{"candidates": []}'))

    def test_validate_schema_types(self):
        errs = validate_schema({"candidates": [{"template_id": 1, "url": "x"}]}, CANDIDATE_SCHEMA)
        self.assertTrue(any("template_id" in e for e in errs))
        errs2 = validate_schema({"candidates": [], "extra": 1}, CANDIDATE_SCHEMA)
        self.assertTrue(any("未声明字段" in e for e in errs2))


class PromptBudgetTest(Setup):
    def test_prompt_capped(self):
        ws = self.make_ws(idor_routes())
        for i in range(40):
            ws.probe.run(ProbeRequest(action_id="s%d" % i,
                                      url="http://app.test/api/users/1?q=x%d&id=%d" % (i, i),
                                      identity="A", label="seed"))
        state = PlannerState.collect(ws, max_assets=40)
        self.assertLessEqual(len(state.prompt_payload()), 8000)


class RunnerTest(Setup):
    def test_loop_confirms_idor_and_stops(self):
        ws = self.seeded()
        good = plan_json({"template_id": "idor-object-ref", "url": IDOR_ROUTE_SEED,
                          "identity_baseline": "A", "identity_probe": "B"},)
        planner = Planner(ws, model=ScriptedClient([good, good, good, good]))
        out = EngagementRunner(ws, planner, max_rounds=2).run()
        statuses = [f["status"] for f in out["findings"]]
        self.assertIn("confirmed", statuses)
        self.assertEqual(out["engagement_id"], "ENG-T")
        self.assertGreater(out["requests"], 0)
        # 第二轮应该因为已确认而不再产出新候选
        self.assertEqual(len(out["rounds"]), 2)

    def test_runner_pauses_on_pending_approval(self):
        from pta.oob import OobCollector
        oob = OobCollector(public_host="127.0.0.1", bind_host="127.0.0.1").start()
        self.addCleanup(oob.stop)
        ws = self.make_ws(idor_routes(), oob=oob)
        cand = plan_json({"template_id": "ssrf-outbound", "url": "http://app.test/api/fetch",
                          "param_path": "query:url"})
        out = EngagementRunner(ws, Planner(ws, model=ScriptedClient([cand] * 3))).run()
        self.assertTrue(out["stop_reason"].startswith("pending_approval"), out["stop_reason"])

    def test_runner_stops_when_budget_exhausted(self):
        ws = self.seeded()
        ws.budget.max_requests = ws.budget.used
        out = EngagementRunner(ws, Planner(ws)).run()
        self.assertEqual(out["stop_reason"], "budget_exhausted")


if __name__ == "__main__":
    unittest.main()
