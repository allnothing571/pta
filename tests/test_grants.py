"""H 项：审批预授权（跑之前批一类）与事后审计。

四层：
  1) 展开 —— 模板的 mutator_hints 怎么变成指纹坐标，不该批的怎么跳过；
  2) 授权 —— dry-run 不写盘、ttl 真的会过期、撤销之后回到 pending；
  3) 审计 —— 真发一发 L2 请求，日志里能看出"是预授权放行的"；
  4) CLI —— 四条命令的退出码与输出。
"""
from __future__ import annotations

import contextlib
import io
import json
import unittest

from pta import grants, vhx
from pta.approvals import LEVEL_ORDER
from pta.executor import Executor
from pta.probe import ProbeRequest
from pta.transport import MockRoute
from support import WorkspaceCase

ENG = "ENG-T"  # 必须与 WorkspaceCase 里 Scope 的 engagement_id 一致


class ExpandTest(unittest.TestCase):
    def test_template_with_hints_expands_to_coords(self):
        specs, skipped = grants.template_specs(["xss-stored-marker"], ["app.test"])
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].param_path, "body:content")
        self.assertEqual(specs[0].payload_class, "stored_xss_marker")
        self.assertEqual(specs[0].level, "L2")
        self.assertEqual(skipped, [])

    def test_template_without_hints_uses_none_coords(self):
        specs, _ = grants.template_specs(["csrf-token-not-enforced"], ["app.test"])
        self.assertEqual(len(specs), 1)
        self.assertIsNone(specs[0].param_path)
        self.assertIsNone(specs[0].payload_class)

    def test_template_not_needing_approval_is_skipped(self):
        specs, skipped = grants.template_specs(["idor-object-ref"], ["app.test"])
        self.assertEqual(specs, [])
        self.assertEqual(skipped[0]["template_id"], "idor-object-ref")
        self.assertIn("不需要审批", skipped[0]["reason"])

    def test_unknown_template_is_an_error(self):
        with self.assertRaises(grants.GrantError):
            grants.template_specs(["no-such-template"], ["app.test"])

    def test_multiple_hosts_expand_per_host(self):
        specs, _ = grants.template_specs(["csrf-token-not-enforced"], ["a.test", "b.test"])
        self.assertEqual(sorted(s.host for s in specs), ["a.test", "b.test"])

    def test_dedupes_identical_coords(self):
        specs, _ = grants.template_specs(
            ["csrf-token-not-enforced", "csrf-token-not-enforced"], ["app.test"])
        self.assertEqual(len(specs), 1)


class ExpandWorkspaceTest(WorkspaceCase):
    def test_defaults_to_scope_domains(self):
        ws = self.make_ws([])
        specs, _ = grants.expand(ws, template_ids=["csrf-token-not-enforced"])
        self.assertEqual([s.host for s in specs], ["app.test"])

    def test_bare_level_is_refused(self):
        ws = self.make_ws([])
        with self.assertRaises(grants.GrantError) as ctx:
            grants.expand(ws, level="L2")
        self.assertIn("整个站", str(ctx.exception))

    def test_mixing_template_and_param_is_refused(self):
        ws = self.make_ws([])
        with self.assertRaises(grants.GrantError):
            grants.expand(ws, template_ids=["csrf-token-not-enforced"],
                          param_path="body:x")

    def test_param_only_is_allowed(self):
        ws = self.make_ws([])
        specs, _ = grants.expand(ws, param_path="body:amount",
                                 payload_class="negative_number")
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].fp,
                         grants.Spec("http_probe", "app.test", "body:amount",
                                     "negative_number", "L2").fp)


class GrantTest(WorkspaceCase):
    def test_dry_run_writes_nothing(self):
        ws = self.make_ws([])
        specs, _ = grants.expand(ws, template_ids=["xss-stored-marker"])
        rows = grants.grant(ws, specs, dry_run=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(grants.listing(ws), [])

    def test_grant_makes_the_gate_pass(self):
        ws = self.make_ws([])
        specs, _ = grants.expand(ws, template_ids=["xss-stored-marker"])
        grants.grant(ws, specs, by="yg", note="今天要跑注入")
        allowed, fp, why = ws.gate.check(ENG, "http_probe", "app.test",
                                         "body:content", "stored_xss_marker", "L2")
        self.assertTrue(allowed, why)
        self.assertEqual(why, "approved:class")
        self.assertEqual(fp, specs[0].fp)

    def test_listing_reports_remaining_time(self):
        ws = self.make_ws([])
        specs, _ = grants.expand(ws, template_ids=["xss-stored-marker"])
        grants.grant(ws, specs, ttl_hours=2)
        rows = grants.listing(ws)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["decided_by"], "operator")
        self.assertGreater(rows[0]["remaining_s"], 60 * 60)
        self.assertLessEqual(rows[0]["remaining_s"], 2 * 3600)

    def test_ttl_is_honoured(self):
        ws = self.make_ws([])
        specs, _ = grants.expand(ws, template_ids=["xss-stored-marker"])
        grants.grant(ws, specs, ttl_hours=-1)  # 立刻过期
        allowed, _, why = ws.gate.check(ENG, "http_probe", "app.test",
                                        "body:content", "stored_xss_marker", "L2")
        self.assertFalse(allowed)
        self.assertEqual(why, "approval_expired")

    def test_revoke_puts_it_back_to_pending(self):
        ws = self.make_ws([])
        specs, _ = grants.expand(ws, template_ids=["xss-stored-marker"])
        grants.grant(ws, specs)
        self.assertEqual(grants.revoke(ws, fp=specs[0].fp), 1)
        allowed, _, why = ws.gate.check(ENG, "http_probe", "app.test",
                                        "body:content", "stored_xss_marker", "L2")
        self.assertFalse(allowed)
        self.assertEqual(why, "pending_approval")

    def test_revoke_by_level_only_touches_that_level(self):
        ws = self.make_ws([])
        grants.grant(ws, [grants.Spec("http_probe", "app.test", "body:a", "p", "L2"),
                          grants.Spec("http_probe", "app.test", "body:b", "p", "L3")])
        self.assertEqual(len(grants.listing(ws)), 2)
        self.assertEqual(grants.revoke(ws, level="L2"), 1)
        left = grants.listing(ws)
        self.assertEqual([r["level"] for r in left], ["L3"])


class AuditTest(WorkspaceCase):
    def _ws_with_route(self):
        return self.make_ws([MockRoute("POST", "app.test", "/api/x", status=200)])

    def test_granted_request_is_logged_with_why(self):
        ws = self._ws_with_route()
        specs, _ = grants.expand(ws, template_ids=["xss-stored-marker"])
        grants.grant(ws, specs, by="yg")
        res = ws.probe.run(ProbeRequest(
            action_id="t1", url="http://app.test/api/x", method="POST",
            identity="A", label="probe", param_path="body:content",
            payload_class="stored_xss_marker", level="L2",
            body_kind="json", body_json={"content": "x"}))
        self.assertEqual(res.status, "ok", res.reason)
        rows = grants.audit(ws, level="L2")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["reason"], "approved:class")
        self.assertEqual(rows[0]["param_path"], "body:content")
        self.assertEqual(rows[0]["evidence_id"], res.evidence_id)

    def test_audit_skips_below_the_floor(self):
        ws = self._ws_with_route()
        ws.store.log_action(ENG, "http_probe",
                             "ok", reason="auto:L1",
                             host="app.test", level="L1",
                             action_id="a")
        ws.store.log_action(ENG, "http_probe",
                             "ok", reason="approved:class",
                             host="app.test", level="L2",
                             action_id="b")
        self.assertEqual([r["level"] for r in grants.audit(ws, level="L2")], ["L2"])
        self.assertEqual(len(grants.audit(ws, level="L1")), 2)

    def test_tally_groups_by_reason(self):
        rows = [{"reason": "approved:class"}, {"reason": "approved:class"},
                {"reason": ""}]
        self.assertEqual(grants.tally(rows), [("approved:class", 2), ("(未记录)", 1)])


class CliTest(WorkspaceCase):
    def setUp(self) -> None:
        super().setUp()
        # make_ws 在这里建好工作区：CLI 每次 open_workspace 都读同一份 scope.json
        self.ws = self.make_ws([])

    def _run(self, argv):
        buf = io.StringIO()
        from pta import cli
        with contextlib.redirect_stdout(buf):
            code = cli.main(argv)
        return code, buf.getvalue()

    def test_grant_dry_run_then_real(self):
        code, out = self._run(["grant", "--root", self.tmp,
                               "--template", "xss-stored-marker", "--dry-run"])
        self.assertEqual(code, 0, out)
        self.assertIn("没有写入", out)
        self.assertEqual(grants.listing(self.ws), [])

        code, out = self._run(["grant", "--root", self.tmp,
                               "--template", "xss-stored-marker", "--json"])
        self.assertEqual(code, 0, out)
        self.assertEqual(len(json.loads(out)["grants"]), 1)

    def test_grants_lists_what_is_live(self):
        self._run(["grant", "--root", self.tmp, "--template", "xss-stored-marker"])
        code, out = self._run(["grants", "--root", self.tmp])
        self.assertEqual(code, 0)
        self.assertIn("stored_xss_marker", out)

    def test_revoke_without_target_is_refused(self):
        code, out = self._run(["revoke", "--root", self.tmp])
        self.assertEqual(code, 1)
        self.assertIn("误删", out)

    def test_audit_json_is_parsable(self):
        code, out = self._run(["audit", "--root", self.tmp, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["actions"], [])


if __name__ == "__main__":
    unittest.main()
