# -*- coding: utf-8 -*-
"""人工标注：改口径、留原判、留可重放的坐标。

这一层要证明三件事：
1. `--fp` 真的把 status 改成 refuted，但**没有**动置信度和判定指标——
   "系统当时有多确信"要留下来，否则事后说不出是哪一步骗过了 oracle；
2. 标注时把 target 快照存下来（URL / 方法 / 两个身份 / 参数位），
   否则标注只是"我记得这条是误报"，变不成回归样本；
3. 误报率的分母是"人看过的那些"。一条都没标过时是 None，不是 0%。
"""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "src"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from pta import labels as labels_mod  # noqa: E402
from test_poc import PocCase  # noqa: E402


class MarkTest(PocCase):
    def test_fp_turns_confirmed_into_refuted(self):
        ws, f = self.make()
        self.assertEqual(f.status, "confirmed", f.verdict)

        res = labels_mod.mark(ws, f.id, label="fp", note="公开资源，不看 id")
        self.assertTrue(res["ok"])
        self.assertEqual(res["original_status"], "confirmed")
        self.assertEqual(res["status"], "refuted")

        row = ws.store.get_finding(f.id)
        self.assertEqual(row["status"], "refuted")
        self.assertEqual(row["overridden_by"], "mark:fp")
        # 置信度是系统当时的判断，不该被人为覆盖。
        self.assertAlmostEqual(row["confidence"], 1.0, places=3)

    def test_original_verdict_is_kept(self):
        """标完之后 metrics / rationale 还要在：复盘要看它是怎么判出来的。"""
        ws, f = self.make()
        labels_mod.mark(ws, f.id, label="fp")

        verdict = json.loads(ws.store.get_finding(f.id)["verdict_json"])
        self.assertIn("similarity", verdict["metrics"])
        self.assertIn("rationale", verdict)
        self.assertEqual(verdict["human_label"]["label"], "fp")
        self.assertEqual(verdict["human_label"]["original_status"], "confirmed")
        # 角色表也不能丢，否则 pta show 又得靠猜。
        self.assertIn("probe", verdict["roles"].values())

    def test_tp_records_who_and_note(self):
        ws, f = self.make()
        labels_mod.mark(ws, f.id, label="tp", note="打回去确实读到别人的单", by="yg")

        row = ws.store.get_finding(f.id)
        self.assertEqual(row["status"], "confirmed")
        self.assertEqual(row["overridden_by"], "mark:tp")
        human = json.loads(row["verdict_json"])["human_label"]
        self.assertEqual(human["by"], "yg")
        self.assertIn("别人的单", human["note"])

    def test_target_snapshot_is_replayable(self):
        """没有这个，标注就只是一句印象，下次没法拿它当回归样本。"""
        ws, f = self.make()
        res = labels_mod.mark(ws, f.id, label="fp")
        self.assertTrue(res["replayable"], res)
        target = res["target"]
        self.assertEqual(target["url"], "http://app.test/api/orders?id=7")
        self.assertEqual(target["method"], "GET")
        self.assertEqual(target["identity_probe"], "bob")
        self.assertEqual(target["identity_baseline"], "alice")
        self.assertEqual(target["param_path"], "query:id")

    def test_clear_restores_system_status(self):
        ws, f = self.make()
        labels_mod.mark(ws, f.id, label="fp")
        self.assertEqual(ws.store.get_finding(f.id)["status"], "refuted")

        res = labels_mod.mark(ws, f.id, clear=True)
        self.assertTrue(res["cleared"])
        row = ws.store.get_finding(f.id)
        self.assertEqual(row["status"], "confirmed")
        self.assertIsNone(row["overridden_by"])
        self.assertNotIn("human_label", json.loads(row["verdict_json"]))

    def test_marking_twice_keeps_both(self):
        """先 fp 后 tp 是真实的：第一眼以为误报，打回去发现是真洞。
        两次都要留，改判本身说明判定和直觉在哪一版分歧。"""
        ws, f = self.make()
        labels_mod.mark(ws, f.id, label="fp")
        labels_mod.mark(ws, f.id, label="tp")

        rows = ws.store.labels(ws.scope.engagement_id)
        self.assertEqual([r["label"] for r in rows], ["fp", "tp"])
        self.assertEqual(ws.store.latest_label(f.id)["label"], "tp")
        self.assertEqual(ws.store.get_finding(f.id)["status"], "confirmed")

    def test_last_marks_newest(self):
        ws, f = self.make()
        res = labels_mod.mark(ws, last=True, label="fp")
        self.assertEqual(res["finding_id"], f.id)

    def test_unknown_finding_is_an_error(self):
        ws, _ = self.make()
        with self.assertRaises(labels_mod.LabelError):
            labels_mod.mark(ws, "nope", label="fp")

    def test_requires_id_or_last(self):
        ws, _ = self.make()
        with self.assertRaises(labels_mod.LabelError):
            labels_mod.mark(ws, None, last=False, label="fp")

    def test_bad_label_is_rejected(self):
        ws, f = self.make()
        with self.assertRaises(labels_mod.LabelError):
            labels_mod.mark(ws, f.id, label="maybe")


class StatsTest(unittest.TestCase):
    def test_rate_is_none_when_nothing_marked(self):
        # 没看过的东西不能算准：0% 会让人以为模板很靠谱。
        self.assertIsNone(labels_mod.rate(0, 0))

    def test_rate_is_fp_over_marked(self):
        self.assertAlmostEqual(labels_mod.rate(1, 3), 0.25)
        self.assertAlmostEqual(labels_mod.rate(2, 0), 1.0)

    def test_stats_counts_by_template(self):
        case = MarkTest("test_fp_turns_confirmed_into_refuted")
        case.setUp()
        try:
            ws, f = case.make()
            labels_mod.mark(ws, f.id, label="fp")
            rows = labels_mod.stats(ws)
            row = [r for r in rows if r["template_id"] == "idor-object-ref"][0]
            self.assertEqual(row["fp"], 1)
            self.assertEqual(row["tp"], 0)
            self.assertAlmostEqual(row["fp_rate"], 1.0)
            self.assertEqual(row["findings"], 1)
            # 系统原判仍是 confirmed：人标了 fp 只是改了最终口径，
            # 不能让"系统判了几条"这个数字跟着人的动作一起漂。
            self.assertEqual(row["confirmed"], 1)
            self.assertEqual(row["refuted"], 0)
        finally:
            case.doCleanups()

    def test_listing_filters_by_label(self):
        case = MarkTest("test_fp_turns_confirmed_into_refuted")
        case.setUp()
        try:
            ws, f = case.make()
            labels_mod.mark(ws, f.id, label="fp", note="公开资源")
            fps = labels_mod.listing(ws, "fp")
            self.assertEqual(len(fps), 1)
            self.assertEqual(fps[0]["note"], "公开资源")
            self.assertEqual(labels_mod.listing(ws, "tp"), [])
        finally:
            case.doCleanups()


class MarkCliTest(PocCase):
    def _run(self, argv):
        from pta import cli

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(argv)
        return code, buf.getvalue()

    def test_mark_last_fp(self):
        self.make()
        code, out = self._run(["mark", "--root", self.root, "--last", "--fp",
                               "--note", "公开资源"])
        self.assertEqual(code, 0, out)
        self.assertIn("已标为误报", out)
        self.assertIn("重放坐标已存", out)

    def test_mark_without_flag_exits_1(self):
        self.make()
        code, out = self._run(["mark", "--root", self.root, "--last"])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])

    def test_stats_shows_dash_when_unmarked(self):
        self.make()
        code, out = self._run(["stats", "--root", self.root])
        self.assertEqual(code, 0, out)
        self.assertIn("idor-object-ref", out)
        self.assertIn("—", out)
        self.assertIn("没看过的东西不能算准", out)

    def test_labels_json(self):
        self.make()
        self._run(["mark", "--root", self.root, "--last", "--fp"])
        code, out = self._run(["labels", "--root", self.root, "--json"])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertEqual(data["labels"][0]["label"], "fp")


if __name__ == "__main__":
    unittest.main()
