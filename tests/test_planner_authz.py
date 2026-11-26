"""Planner 自动提出缺失授权候选：/api/* 类端点 + 用真实 401/403 当拒绝模板。"""
from __future__ import annotations

import copy
import json
import unittest

from pta import vhx
from pta.executor import Executor, Target
from pta.llm import ScriptedClient
from pta.planner import Candidate, Planner, PlannerState, heuristic_candidates
from pta.probe import ProbeRequest
from pta.transport import MockRoute
from support import WorkspaceCase

from urllib.parse import urlsplit

ORDERS = b'{"orders":[{"id":1001,"amount":88.5}],"user":"alice"}'
DENY = b'{"error":"forbidden"}'
JSON_HEAD = (("Content-Type", "application/json"),)
HTML_HEAD = (("Content-Type", "text/html; charset=utf-8"),)


def authz_routes(orders_status: int = 200, audit: bool = True, extra=()):
    out = [MockRoute("GET", "app.test", "/api/orders", orders_status, JSON_HEAD, ORDERS)]
    if audit:
        out.append(MockRoute("GET", "app.test", "/admin/audit", 403, JSON_HEAD, DENY))
    out.extend(extra)
    return out


class Base(WorkspaceCase):
    def seeded(self, routes=None, identity: str = "A", url: str = "http://app.test/api/orders",
               audit: bool = True):
        ws = self.make_ws(routes if routes is not None else authz_routes())
        ws.probe.run(ProbeRequest(action_id="seed", url=url, identity=identity, label="seed"))
        if audit:
            ws.probe.run(ProbeRequest(action_id="seed-audit", url="http://app.test/admin/audit",
                                      identity="A", label="seed"))
        return ws


def authz_template():
    raw = [t for t in vhx.TEMPLATES if t["id"] == "authz-missing-endpoint"][0]
    return vhx.load(copy.deepcopy(raw))


class ProposeTest(Base):
    def test_proposes_authz_for_api_endpoint(self):
        plan = Planner(self.seeded()).plan()
        cands = [c for c in plan.candidates if c.template_id == "authz-missing-endpoint"]
        self.assertEqual(len(cands), 1, plan.to_json())
        c = cands[0]
        self.assertEqual(urlsplit(c.url).path, "/api/orders")
        self.assertEqual(c.identity_baseline, "A")
        self.assertEqual(c.identity_probe, "none")     # 不带凭据才算复核
        self.assertEqual(c.source, "rule")

    def test_uses_real_denial_as_control(self):
        plan = Planner(self.seeded()).plan()
        c = [x for x in plan.candidates if x.template_id == "authz-missing-endpoint"][0]
        self.assertTrue(c.control_url and c.control_url.endswith("/admin/audit"), c.control_url)
        self.assertEqual(c.priority, 0.78)
        self.assertIn("拒绝模板", c.rationale)

    def test_without_denial_lowers_priority(self):
        ws = self.seeded(audit=False)
        c = [x for x in Planner(ws).plan().candidates
             if x.template_id == "authz-missing-endpoint"][0]
        self.assertIsNone(c.control_url)
        self.assertEqual(c.priority, 0.70)
        self.assertIn("无拒绝模板", c.rationale)

    def test_skips_when_no_identity_can_read(self):
        ws = self.seeded(identity="none", audit=False)
        ids = [c.template_id for c in Planner(ws).plan().candidates]
        self.assertNotIn("authz-missing-endpoint", ids)

    def test_skips_plain_html_page(self):
        extra = [MockRoute("GET", "app.test", "/about", 200, HTML_HEAD, b"<html>hi</html>")]
        ws = self.seeded(routes=authz_routes(extra=extra), url="http://app.test/about",
                         audit=False)
        urls = [c.url for c in Planner(ws).plan().candidates
                if c.template_id == "authz-missing-endpoint"]
        self.assertFalse([u for u in urls if u.endswith("/about")], urls)

    def test_json_content_type_counts_as_endpoint(self):
        extra = [MockRoute("GET", "app.test", "/feed", 200, JSON_HEAD, b'[{"id":1}]')]
        ws = self.seeded(routes=authz_routes(extra=extra), url="http://app.test/feed",
                         audit=False)
        urls = [c.url for c in Planner(ws).plan().candidates
                if c.template_id == "authz-missing-endpoint"]
        self.assertTrue([u for u in urls if u.endswith("/feed")], urls)

    def test_skips_non_200_asset(self):
        ws = self.seeded(routes=authz_routes(orders_status=500), audit=False)
        ids = [c.template_id for c in Planner(ws).plan().candidates]
        self.assertNotIn("authz-missing-endpoint", ids)

    def test_planner_still_sends_nothing(self):
        ws = self.seeded()
        sent, used = len(ws.transport.sent), ws.budget.used
        Planner(ws).plan()
        self.assertEqual(len(ws.transport.sent), sent)
        self.assertEqual(ws.budget.used, used)


class ControlHygieneTest(Base):
    def _model(self, control):
        raw = {"template_id": "authz-missing-endpoint", "url": "http://app.test/api/orders",
               "identity_baseline": "A", "identity_probe": "none", "control_url": control}
        return ScriptedClient([json.dumps({"candidates": [raw]})])

    def test_out_of_scope_control_dropped(self):
        plan = Planner(self.seeded(), model=self._model("https://evil.test/admin")).plan()
        c = [x for x in plan.candidates if x.template_id == "authz-missing-endpoint"][0]
        self.assertIsNone(c.control_url)
        self.assertIn("丢弃", c.rationale)

    def test_same_path_control_dropped(self):
        plan = Planner(self.seeded(), model=self._model("http://app.test/api/orders")).plan()
        c = [x for x in plan.candidates if x.template_id == "authz-missing-endpoint"][0]
        self.assertIsNone(c.control_url)
        self.assertIn("同一路径", c.rationale)

    def test_model_control_kept_when_valid(self):
        plan = Planner(self.seeded(),
                       model=self._model("http://app.test/admin/audit")).plan()
        c = [x for x in plan.candidates if x.template_id == "authz-missing-endpoint"][0]
        self.assertEqual(c.control_url, "http://app.test/admin/audit")
        self.assertEqual(c.source, "model")

    def test_prompt_carries_rule_candidates(self):
        ws = self.seeded()
        text = PlannerState.collect(ws).prompt_payload()
        self.assertIn("rule_candidates", text)
        self.assertIn("authz-missing-endpoint", text)


class WiringTest(Base):
    def test_candidate_control_reaches_executor(self):
        ws = self.seeded()
        cand = [x for x in Planner(ws).plan().candidates
                if x.template_id == "authz-missing-endpoint"][0]
        finding = Executor(ws.probe, ws.store, ws.scope.engagement_id).run(
            authz_template(), cand.to_target())
        self.assertEqual(finding.status, "confirmed", finding.to_json())
        self.assertGreaterEqual(finding.confidence, 0.90)
        self.assertEqual(len(finding.evidence_ids), 3)     # baseline + control + probe
        self.assertTrue(finding.verdict.get("metrics", {}).get("deny_template"))

    def test_already_found_is_not_reproposed(self):
        ws = self.seeded()
        cand = [x for x in Planner(ws).plan().candidates
                if x.template_id == "authz-missing-endpoint"][0]
        Executor(ws.probe, ws.store, ws.scope.engagement_id).run(
            authz_template(), cand.to_target())
        plan = Planner(ws).plan()
        ids = [c.template_id for c in plan.candidates]
        self.assertNotIn("authz-missing-endpoint", ids)
        reasons = [r["reason"] for r in plan.rejected]
        self.assertIn("already_found", reasons)


if __name__ == "__main__":
    unittest.main()
