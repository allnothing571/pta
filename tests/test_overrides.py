"""覆盖层：校准结果怎么生效，以及"只调阈值、不改判定"这条线守不守得住。"""
from __future__ import annotations

import copy
import json
import os
import unittest

from pta import overrides as ov
from pta import vhx
from pta.executor import Executor, Target
from pta.transport import MockRoute, MockTransport

from support import WorkspaceCase

TID = "sqli-time-blind"
URL = "http://app.test/api/item?id=7"


def _raw(template_id: str = TID):
    for raw in vhx.TEMPLATES:
        if raw["id"] == template_id:
            return copy.deepcopy(raw)
    raise AssertionError("模板不存在：%s" % template_id)


class MergeTest(unittest.TestCase):
    def test_thresholds_are_merged_into_a_copy(self):
        raw = _raw()
        before = raw["oracle"]["args"]["min_effect_ms"]
        merged = ov.apply_to(raw, {"oracle": {"args": {"min_effect_ms": 250}}})
        self.assertEqual(merged["oracle"]["args"]["min_effect_ms"], 250)
        # 原模板对象必须原封不动：同一进程里它还要服务别的目标
        self.assertEqual(raw["oracle"]["args"]["min_effect_ms"], before)

    def test_scalar_leaf_is_overwritten_not_merged(self):
        merged = ov.apply_to(_raw(), {"probe": {"samples": 12}})
        self.assertEqual(merged["probe"]["samples"], 12)
        # 兄弟字段不受影响
        self.assertEqual(merged["budget"], _raw()["budget"])

    def test_empty_fragment_changes_nothing(self):
        self.assertEqual(ov.apply_to(_raw(), {}), _raw())


class GuardTest(unittest.TestCase):
    """覆盖层只能调阈值。任何能改变"判什么/多危险"的字段都必须被拒。"""

    def test_side_effect_level_is_rejected(self):
        with self.assertRaises(ov.OverrideError) as ctx:
            ov.apply_to(_raw(), {"side_effect_level": "L0"})
        self.assertIn("side_effect_level", str(ctx.exception))
        self.assertIn("只允许调", str(ctx.exception))

    def test_oracle_name_is_rejected(self):
        with self.assertRaises(ov.OverrideError):
            ov.apply_to(_raw(), {"oracle": {"name": "error_signature_match"}})

    def test_requires_approval_is_rejected(self):
        with self.assertRaises(ov.OverrideError):
            ov.apply_to(_raw(), {"requires_approval": False})

    def test_lowering_budget_is_rejected(self):
        # 预算是硬上限，让它可覆盖等于让覆盖层给自己加预算
        with self.assertRaises(ov.OverrideError):
            ov.apply_to(_raw(), {"budget": {"max_requests": 9999}})

    def test_mutator_hints_are_rejected(self):
        with self.assertRaises(ov.OverrideError):
            ov.apply_to(_raw(), {"mutator_hints": []})

    def test_nested_object_value_is_rejected(self):
        with self.assertRaises(ov.OverrideError):
            ov.apply_to(_raw(), {"oracle": {"args": {"signatures": {"x": ["y"]}}}})


class StoreTest(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.ws = self.make_ws([])

    def test_roundtrip_and_path(self):
        frag = {"oracle": {"args": {"cv_max": 0.5}}, "probe": {"samples": 10}}
        path = ov.write(self.ws, {TID: frag})
        self.assertEqual(path, ov.path_for(self.ws))
        self.assertEqual(os.path.basename(path), "overrides.json")
        self.assertEqual(ov.read(self.ws), {TID: frag})
        with open(path, "r", encoding="utf-8") as fh:
            body = json.load(fh)
        self.assertEqual(body["version"], 1)

    def test_bad_fragment_never_lands_on_disk(self):
        # 全量校验先跑：宁可写不进去，也不留下半份能绕门的覆盖
        with self.assertRaises(ov.OverrideError):
            ov.write(self.ws, {TID: {"oracle": {"args": {"min_effect_ms": 100}},
                                     "side_effect_level": "L0"}})
        self.assertFalse(os.path.exists(ov.path_for(self.ws)))

    def test_clear(self):
        ov.write(self.ws, {TID: {"probe": {"samples": 8}}})
        self.assertTrue(ov.clear(self.ws))
        self.assertFalse(ov.clear(self.ws))
        self.assertEqual(ov.read(self.ws), {})

    def test_missing_file_reads_empty(self):
        self.assertEqual(ov.read(self.ws), {})


class LoadTest(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.ws = self.make_ws([])

    def test_load_template_applies_and_returns_fragment(self):
        ov.write(self.ws, {TID: {"oracle": {"args": {"min_effect_ms": 300}},
                                 "probe": {"samples": 9}}})
        tpl, frag = ov.load_template(self.ws, TID)
        self.assertEqual(tpl.raw["oracle"]["args"]["min_effect_ms"], 300)
        self.assertEqual(tpl.raw["probe"]["samples"], 9)
        self.assertEqual(frag["probe"]["samples"], 9)
        # 判定本身没被动过
        self.assertEqual(tpl.raw["oracle"]["name"], "timing_distribution_shift")
        self.assertEqual(tpl.raw["side_effect_level"], "L2")

    def test_load_template_without_overrides_is_the_builtin(self):
        tpl, frag = ov.load_template(self.ws, TID)
        self.assertEqual(frag, {})
        self.assertEqual(tpl.raw["oracle"]["args"],
                         _raw()["oracle"]["args"])

    def test_unknown_template_raises(self):
        with self.assertRaises(KeyError):
            ov.load_template(self.ws, "no-such-template")

    def test_describe_lists_paths(self):
        lines = ov.describe({TID: {"oracle": {"args": {"cv_max": 0.4}},
                                   "probe": {"samples": 9}}})
        self.assertTrue(any("oracle.args.cv_max = 0.4" in l for l in lines), lines)
        self.assertTrue(any("probe.samples = 9" in l for l in lines), lines)


class SuggestionTest(unittest.TestCase):
    def test_only_tuning_keys_are_carried_over(self):
        frag = ov.from_suggestion({"min_samples": 9, "samples": 10, "cv_max": 0.5,
                                   "abs_noise_ms": 89.5, "min_effect_ms": 1200,
                                   "verdict": "noisy", "p50": 110.8})
        self.assertEqual(frag["probe"]["samples"], 10)
        self.assertEqual(frag["oracle"]["args"],
                         {"min_samples": 9, "cv_max": 0.5, "abs_noise_ms": 89.5,
                          "min_effect_ms": 1200})

    def test_empty_suggestion_produces_empty_fragment(self):
        self.assertEqual(ov.from_suggestion({}), {})


class SlowTransport(MockTransport):
    """基线 30ms、带 SLEEP 的请求 400ms：同一份样本，只靠阈值决定判不判。"""

    def __init__(self, probe_ms: float = 400.0):
        super().__init__([MockRoute("GET", "app.test", "/api/item", 200,
                                    (("Content-Type", "application/json"),), b'{"ok":true}')])
        self.probe_ms = probe_ms
        self.n = 0

    def send(self, req, timeout_s: float = 10.0):
        q = "&".join("%s=%s" % (k, v) for k, v in req.query)
        self.n += 1
        base = self.probe_ms if "SLEEP" in q else 30.0
        self.routes[0].delay_ms = base
        return super().send(req, timeout_s)


class EffectiveTest(WorkspaceCase):
    """端到端：同一份延时数据，覆盖层换了阈值，结论就变了。"""

    def run_tpl(self, ws):
        ws.gate.decide("ENG-T", "http_probe", "app.test", "query:id", "delay_short",
                       "L2", "approve", scope="class")
        tpl, _frag = ov.load_template(ws, TID)
        target = Target(url=URL, method="GET", param_path="query:id",
                        identity_baseline="A", identity_probe="A")
        return Executor(ws.probe, ws.store, "ENG-T").run(tpl, target)

    def test_builtin_threshold_refutes_400ms(self):
        ws = self.make_ws([], transport=SlowTransport(400.0))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertIn("低于阈值", f.verdict["rationale"])

    def test_override_lowers_threshold_and_confirms(self):
        ws = self.make_ws([], transport=SlowTransport(400.0))
        ov.write(ws, {TID: {"oracle": {"args": {"min_effect_ms": 150}}}})
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.90)
        # 覆盖只改阈值，采样次数仍是模板默认（6 发 5 计）
        self.assertEqual(f.verdict["metrics"]["probe_samples"], 5)

    def test_override_can_raise_sample_count(self):
        ws = self.make_ws([], transport=SlowTransport(400.0))
        ov.write(ws, {TID: {"oracle": {"args": {"min_effect_ms": 150}},
                            "probe": {"samples": 9}}})
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "confirmed", f.verdict)
        # probe.samples 是"发几次"，执行器先丢 1 个冷启动 → 9 发 8 计。
        # 所以校准器给的建议恒为 min_samples + 1（见 calibrate._suggest）。
        self.assertEqual(f.verdict["metrics"]["probe_samples"], 8)
        for ev_id in f.evidence_ids:
            self.assertEqual(len(ws.store.timings(ev_id)), 9)


if __name__ == "__main__":
    unittest.main()
