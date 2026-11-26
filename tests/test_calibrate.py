"""校准器测试：给已知分布，看它把哪三个阈值算成什么。

重点不是"数字对不对到小数点"，而是三条边界：
1. 稳态端点 → 建议值贴着地板，判 ok；
2. 抖动端点 → cv_max 被放宽、判 noisy，但仍给得出一组可用阈值；
3. 0ms 采样（时钟粒度）→ 判 clock，不硬算分布。
"""
from __future__ import annotations

import json
import os
import random
import time
import unittest

from pta.calibrate import Calibration, Calibrator, write_calibration
from pta.models import RawResponse
from pta.transport import Transport

from support import WorkspaceCase


class TimingTransport(Transport):
    """按第 n 次请求给出可预测的耗时（毫秒）。"""

    name = "timing"

    def __init__(self, fn, status=200, body=b'{"ok":true}'):
        self.fn = fn
        self.status = status
        self.body = body
        self.n = 0
        self.sent = []

    def send(self, req, timeout_s=10.0):
        self.n += 1
        self.sent.append(req)
        delay = self.fn(self.n) or 0.0
        t0 = time.perf_counter()
        if delay > 0:
            # 直接构造时间戳而不真的 sleep：这里要测的是校准器的算术，
            # 不是操作系统的 sleep 精度（真 sleep 30ms 会量出 30.0~33.x，
            # 让 cv 在 0~0.11 之间漂，测试就变成掷骰子）。
            t1 = t0 + delay / 1000.0
        else:
            # 0 表示"时钟没走到下一格"：三个时间戳取同一个读数
            t1 = t0
        return RawResponse(
            status=self.status,
            reason="OK" if self.status < 400 else "ERR",
            http_version="HTTP/1.1",
            headers=(("Content-Type", "application/json"),),
            body=self.body,
            t_send=t0,
            t_first_byte=t1,
            t_end=t1,
        )


URL = "http://app.test/api/items"


def calibrate(ws, **kw):
    kw.setdefault("samples", 12)
    return Calibrator(ws, kw.pop("url", URL), **kw).run()


class StatsTest(unittest.TestCase):
    def test_median_mad_and_quantiles(self):
        cal = Calibration(url="x", samples=[10.0, 12.0, 14.0, 16.0, 18.0])
        self.assertEqual(cal.p50, 14.0)
        self.assertEqual(cal.mad, 2.0)          # |10-14|=4, |12-14|=2, 0, 2, 4 → 中位 2
        self.assertAlmostEqual(cal.cv, 2.0 / 14.0, places=6)
        self.assertEqual(cal.peak, 18.0)
        self.assertEqual(cal.low, 10.0)
        self.assertEqual(cal.spread, 8.0)
        self.assertAlmostEqual(cal.p90, 17.2, places=6)   # 线性插值：16 + 0.6*(18-16)

    def test_empty_is_zero_not_crash(self):
        cal = Calibration(url="x")
        self.assertEqual(cal.p50, 0.0)
        self.assertEqual(cal.cv, 0.0)
        self.assertEqual(cal.to_json()["stats"]["count"], 0.0)


class SteadyTest(WorkspaceCase):
    def test_steady_endpoint_suggests_floor_values(self):
        tx = TimingTransport(lambda n: 30.0 + (0.5 if n % 2 else -0.5))
        ws = self.make_ws([], transport=tx)
        cal = calibrate(ws)
        self.assertEqual(cal.verdict, "ok", cal.reason)
        self.assertEqual(cal.notes, [])
        self.assertEqual(cal.suggestion["cv_max"], 0.15)
        self.assertLessEqual(cal.suggestion["min_effect_ms"], 1000)
        self.assertGreaterEqual(cal.suggestion["min_effect_ms"], 500)
        self.assertEqual(cal.suggestion["min_samples"], 5)
        self.assertEqual(cal.suggestion["samples"], 6)     # 多要 1 个用来丢冷启动
        self.assertEqual(cal.warmup_dropped, 1)
        # 30ms 端点 + 12 次采样 = 至少 12 次请求，预算与审计都跟着走
        self.assertEqual(len(tx.sent), 12)
        self.assertEqual(ws.budget.used, 12)

    def test_fast_endpoint_does_not_invent_a_huge_effect(self):
        # 2ms 端点：相对抖动天然大（调度噪声占大头），判 noisy 是诚实的结果，
        # 但阈值必须落在地板上——不能因为 2ms 抖动就配 60ms 的"效应量"。
        tx = TimingTransport(lambda n: 2.0)
        ws = self.make_ws([], transport=tx)
        cal = calibrate(ws, samples=8)
        self.assertEqual(cal.suggestion["min_effect_ms"], 500)
        self.assertLessEqual(cal.suggestion["cv_max"], 0.5)

    def test_small_absolute_jitter_is_not_noise(self):
        # 30ms 端点抖 ±6~10ms：cv≈0.20 超过 0.15，但绝对抖动只有 6ms。
        # Windows 定时器量化就是 15.6ms，这种"偏高"是分母小，不是目标不稳；
        # 判 noisy 会把 cv_max 放宽到 0.4，等于自己拆掉灵敏度闸。
        seq = (20.0, 36.0, 24.0, 36.0, 30.0, 36.0, 24.0, 36.0, 20.0)
        tx = TimingTransport(lambda n: seq[(n - 2) % len(seq)] if n > 1 else 30.0)
        ws = self.make_ws([], transport=tx)
        cal = calibrate(ws, samples=10)
        self.assertGreater(cal.cv, 0.15)
        self.assertLessEqual(cal.mad, 8.0)
        self.assertEqual(cal.verdict, "ok", cal.reason)
        self.assertEqual(cal.suggestion["cv_max"], 0.15)
        self.assertIn("分母小", cal.reason)


class NoisyTest(WorkspaceCase):
    def test_jittery_endpoint_widens_cv_and_raises_effect(self):
        rnd = random.Random(7)
        tx = TimingTransport(lambda n: 20.0 + rnd.uniform(0, 240))
        ws = self.make_ws([], transport=tx)
        cal = calibrate(ws, samples=16)
        self.assertEqual(cal.verdict, "noisy", cal.reason)
        self.assertGreaterEqual(cal.suggestion["cv_max"], 0.30)
        self.assertLessEqual(cal.suggestion["cv_max"], 0.50)
        self.assertGreaterEqual(cal.suggestion["min_effect_ms"], 500)
        self.assertEqual(cal.suggestion["min_samples"], 9)
        self.assertEqual(cal.suggestion["samples"], 10)
        self.assertTrue(any("离散度" in n or "噪声" in n for n in cal.notes) or cal.reason)

    def test_very_slow_endpoint_gets_a_hint(self):
        tx = TimingTransport(lambda n: 2100.0)
        ws = self.make_ws([], transport=tx)
        cal = calibrate(ws, samples=6)
        self.assertTrue(cal.notes)
        self.assertTrue(any("端点本身" in n for n in cal.notes), cal.notes)


class DegenerateTest(WorkspaceCase):
    def test_zero_ms_samples_are_a_clock_problem(self):
        tx = TimingTransport(lambda n: 0.0)
        ws = self.make_ws([], transport=tx)
        cal = calibrate(ws, samples=8)
        self.assertEqual(cal.verdict, "clock")
        self.assertIn("0ms", cal.reason)
        self.assertEqual(cal.zeros, 8)
        self.assertEqual(cal.suggestion, {})

    def test_unreachable_target_stops_early(self):
        tx = TimingTransport(lambda n: 5.0, status=403)
        ws = self.make_ws([], transport=tx)
        cal = calibrate(ws, samples=8)
        self.assertEqual(cal.verdict, "unreachable")
        self.assertIn("403", cal.reason)
        self.assertEqual(len(tx.sent), 1, "第一次被拒就该停，别把预算耗在 403 上")

    def test_budget_is_respected(self):
        tx = TimingTransport(lambda n: 20.0)
        ws = self.make_ws([], transport=tx)
        ws.budget.max_requests = 4
        cal = calibrate(ws, samples=20)
        self.assertLessEqual(ws.budget.used, 4)
        self.assertTrue(any("预算" in n for n in cal.notes), cal.notes)


class ReportTest(WorkspaceCase):
    def test_json_shape_and_write(self):
        tx = TimingTransport(lambda n: 25.0)
        ws = self.make_ws([], transport=tx)
        cal = calibrate(ws, samples=8)
        path = write_calibration(ws, cal)
        self.assertTrue(os.path.exists(path))
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["url"], URL)
        self.assertIn("p50_ms", data["stats"])
        self.assertIn("min_effect_ms", data["suggestion"])
        self.assertEqual(data["verdict"], "ok")
        # 内容寻址的结果：N 次"同一个请求"只剩 1 条证据、N 条 timing_sample
        self.assertEqual(len(tx.sent), 8)
        self.assertEqual(len(ws.store.list_evidence("ENG-T")), 1)
        self.assertEqual(len(ws.store.timings(ws.store.list_evidence("ENG-T")[0]["evidence_id"])), 8)


if __name__ == "__main__":
    unittest.main()
