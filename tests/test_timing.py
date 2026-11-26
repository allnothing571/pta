"""sqli-time-blind：时间分布 oracle + 执行链（含"同身份对照"这个坑）。"""
from __future__ import annotations

import copy
import unittest
from typing import Any, Dict, List

from pta import vhx
from pta.critic import Critic
from pta.executor import Executor, Target
from pta.oracles import Observation, ORACLE_REGISTRY, TimingDistributionShift
from pta.transport import MockRoute, MockTransport

from support import WorkspaceCase

URL = "http://app.test/api/item?id=7"


def _obs(role: str, timings: List[float], status: int = 200,
         sha: str = "b" * 64) -> Observation:
    return Observation(
        role=role, evidence_id="%s-1" % role, identity="A", method="GET",
        url=URL, status=status, content_type="application/json",
        body_sha256=sha, body_len=2, body=b"{}", headers={},
        timings=tuple(float(t) for t in timings),
    )


def _verdict(base: List[float], probe: List[float], **kw):
    args = TimingDistributionShift.Args(**kw)
    return TimingDistributionShift().run([_obs("baseline", base), _obs("probe", probe)], args)


STEADY = [28.0, 30.0, 31.0, 29.0, 32.0]


class OracleTest(unittest.TestCase):
    def test_confirmed_when_injection_sleeps(self):
        v = _verdict(STEADY, [2028.0, 2031.0, 2030.0, 2029.0, 2032.0])
        self.assertTrue(v.passed, v.rationale)
        self.assertGreaterEqual(v.confidence, 0.90)
        self.assertLess(v.metrics["p_value"], 0.01)
        self.assertGreaterEqual(v.metrics["effect_ms"], 1800)

    def test_bigger_effect_gets_higher_confidence(self):
        v = _verdict(STEADY, [2801.0, 2802.0, 2800.0, 2803.0, 2800.0])
        self.assertTrue(v.passed)
        self.assertGreaterEqual(v.confidence, 0.94)

    def test_small_effect_is_refuted(self):
        v = _verdict(STEADY, [328.0, 330.0, 331.0, 329.0, 332.0])
        self.assertFalse(v.passed)
        self.assertLess(v.confidence, 0.20)
        self.assertIn("低于阈值", v.rationale)

    def test_jittery_samples_are_not_trusted(self):
        noisy = [10.0, 400.0, 30.0, 900.0, 60.0]
        v = _verdict(noisy, [2028.0, 2031.0, 2030.0, 2029.0, 2032.0])
        self.assertFalse(v.passed)
        self.assertLess(v.confidence, 0.20)
        self.assertIn("抖动", v.rationale)
        self.assertGreater(v.metrics["cv_baseline"], 0.15)

    def test_insufficient_samples_list_what_is_missing(self):
        v = _verdict([30.0, 31.0, 30.0], [2030.0, 2031.0, 2030.0])
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("baseline:timings", v.missing_evidence)
        self.assertIn("probe:timings", v.missing_evidence)

    def test_no_baseline_is_not_evidence(self):
        v = TimingDistributionShift().run(
            [_obs("probe", [2030.0] * 5)], TimingDistributionShift.Args())
        self.assertFalse(v.passed)
        self.assertEqual(v.missing_evidence, ("baseline",))

    def test_probe_403_is_refuted(self):
        v = _verdict(STEADY, [3030.0] * 5, )
        self.assertTrue(v.passed)   # 200 时正常
        v = _verdict(STEADY, [3030.0] * 5)
        self.assertTrue(v.passed)
        v403 = TimingDistributionShift().run(
            [_obs("baseline", STEADY), _obs("probe", [3030.0] * 5, status=403)],
            TimingDistributionShift.Args())
        self.assertFalse(v403.passed)
        self.assertEqual(v403.confidence, 0.0)
        self.assertIn("拒绝", v403.rationale)

    def test_probe_500_is_refuted(self):
        v = TimingDistributionShift().run(
            [_obs("baseline", STEADY), _obs("probe", [3030.0] * 5, status=500)],
            TimingDistributionShift.Args())
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)

    def test_alpha_gate_rejects_weak_significance(self):
        v = _verdict(STEADY, [2030.0] * 5, alpha=1e-12)
        self.assertFalse(v.passed)
        self.assertIn("不显著", v.rationale)
        self.assertLessEqual(v.confidence, 0.25)

    def test_same_input_same_p_value(self):
        base = [28.0, 30.0, 31.0, 29.0, 32.0, 33.0, 27.0]
        probe = [2028.0, 2031.0, 2030.0, 2029.0, 2032.0, 2027.0, 2033.0]
        a = _verdict(base, probe)
        b = _verdict(base, probe)
        self.assertEqual(a.metrics["p_value"], b.metrics["p_value"])
        self.assertEqual(a.metrics["seed"], b.metrics["seed"])
        self.assertEqual(a.confidence, b.confidence)

    def test_zero_ms_samples_say_clock_precision(self):
        # 0.0ms 不是"很快"，是"这个时钟量不出来"（Windows 上 monotonic 粒度 15.6ms）
        base = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        probe = [2030.0] * 6
        v = _verdict(base, probe)
        self.assertFalse(v.passed)
        self.assertEqual(v.confidence, 0.0)
        self.assertIn("时钟精度", v.rationale)
        self.assertIn("baseline:timings", v.missing_evidence)
        self.assertEqual(v.metrics["zero_baseline"], 6)

    def test_sub_millisecond_jitter_is_not_noise(self):
        # 内网 2ms 接口：相对离散度会被放大到阈值以上，但绝对抖动 < 1ms
        base = [1.0, 1.2, 1.4, 1.8, 2.6]
        probe = [2020.0, 2021.0, 2019.0, 2022.0, 2020.0]
        v = _verdict(base, probe)
        self.assertTrue(v.passed, v.rationale)
        self.assertGreater(v.metrics["cv_baseline"], 0.15)
        self.assertLess(v.metrics["mad_baseline_ms"], 5.0)

    def test_extreme_relative_noise_still_rejects(self):
        # 相对离散度离谱时，差值再大也不能归因（中位数本身没意义）
        base = [10.0, 4000.0, 30.0, 9000.0, 60.0]
        probe = [2028.0, 2031.0, 2030.0, 2029.0, 2032.0]
        v = _verdict(base, probe)
        self.assertFalse(v.passed)
        self.assertIn("抖动", v.rationale)
        self.assertGreater(v.metrics["cv_baseline"], 4.0 * 0.15)


class TimingTransport(MockTransport):
    """基线 ~30ms，带 SLEEP 的请求 ~1900ms；抖动 1ms，CV 远低于阈值。"""

    def __init__(self, base_ms: float = 30.0, probe_ms: float = 1900.0):
        super().__init__([MockRoute("GET", "app.test", "/api/item", 200,
                                    (("Content-Type", "application/json"),), b'{"ok":true}')])
        self.base_ms, self.probe_ms = base_ms, probe_ms
        self.n = 0

    def send(self, req, timeout_s: float = 10.0):
        q = "&".join("%s=%s" % (k, v) for k, v in req.query)
        self.n += 1
        base = self.probe_ms if "SLEEP" in q else self.base_ms
        self.routes[0].delay_ms = base + (1.0 if self.n % 2 else -1.0)
        return super().send(req, timeout_s)


def _raw(**oracle_args: Any) -> Dict[str, Any]:
    for raw in vhx.TEMPLATES:
        if raw["id"] == "sqli-time-blind":
            t = copy.deepcopy(raw)
            t["oracle"]["args"].update(oracle_args)
            return t
    raise AssertionError("模板 sqli-time-blind 不存在")


def _tmpl(**oracle_args: Any) -> vhx.Template:
    return vhx.load(_raw(**oracle_args))


class ExecutorTest(WorkspaceCase):
    def run_tpl(self, ws, approve: bool = True, **oracle_args):
        if approve:
            ws.gate.decide("ENG-T", "http_probe", "app.test", "query:id", "delay_short",
                           "L2", "approve", scope="class")
        target = Target(url=URL, method="GET", param_path="query:id",
                        identity_baseline="A", identity_probe="A")
        # 测试里把阈值压到 200ms：真 SLEEP(2) 太慢，判定逻辑与阈值取值无关
        args = {"min_effect_ms": 200}
        args.update(oracle_args)
        return Executor(ws.probe, ws.store, "ENG-T").run(_tmpl(**args), target)

    def test_confirmed_with_five_samples_each(self):
        tx = TimingTransport(probe_ms=400.0)
        ws = self.make_ws([], transport=tx)
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "confirmed", f.verdict)
        self.assertGreaterEqual(f.confidence, 0.90)
        self.assertEqual(len(f.evidence_ids), 2)
        self.assertEqual(f.verdict["metrics"]["baseline_samples"], 5)
        self.assertEqual(f.verdict["metrics"]["probe_samples"], 5)
        self.assertEqual(f.verdict["metrics"]["warmup_dropped"], 2)
        self.assertEqual(len(tx.sent), 12)        # 6 基线 + 6 注入（各丢首样本）
        crit = Critic(ws).review_finding(f)
        self.assertEqual(crit.status, "kept", crit.blocks)

    def test_no_sleep_is_refuted(self):
        ws = self.make_ws([], transport=TimingTransport(base_ms=30.0, probe_ms=30.0))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "refuted", f.verdict)
        self.assertLess(f.confidence, 0.20)

    def test_l2_needs_approval_and_sends_no_payload(self):
        tx = TimingTransport(probe_ms=400.0)
        ws = self.make_ws([], transport=tx)
        f = self.run_tpl(ws, approve=False)
        self.assertTrue(f.stop_reason.startswith("pending_approval"), f.stop_reason)
        self.assertFalse(any("SLEEP" in "&".join("%s=%s" % (k, v) for k, v in r.query)
                             for r in tx.sent))
        self.assertEqual(f.evidence_ids, [])

    def test_evidence_keeps_all_timings(self):
        ws = self.make_ws([], transport=TimingTransport(probe_ms=400.0))
        f = self.run_tpl(ws)
        self.assertEqual(f.status, "confirmed")
        for ev_id in f.evidence_ids:
            self.assertEqual(len(ws.store.timings(ev_id)), 6)
            self.assertEqual(ws.store.get_evidence_row(ev_id)["sample_count"], 6)


class TemplateMetaTest(unittest.TestCase):
    def test_template_is_valid_and_l2(self):
        raw = _raw()
        self.assertEqual(vhx.lint(raw), [])
        self.assertEqual(raw["side_effect_level"], "L2")
        self.assertTrue(raw["requires_approval"])
        self.assertIn("timing_sample", raw["probe"]["sequence"])
        self.assertIn(raw["oracle"]["name"], ORACLE_REGISTRY)

    def test_template_requires_sampling(self):
        raw = _raw()
        args = raw["oracle"]["args"]
        self.assertGreaterEqual(int(args["min_samples"]), 5)
        # 每组 = min_samples 个有效点 + 1 个冷启动样本
        self.assertGreaterEqual(int(raw["budget"]["min_requests"]),
                                2 * (int(args["min_samples"]) + 1))


if __name__ == "__main__":
    unittest.main()
