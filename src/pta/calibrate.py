"""时间类判定的现场校准：先在目标上量噪声，再给出阈值建议。

为什么需要这一层：
`timing_distribution_shift` 默认 `cv_max=0.15` / `min_effect_ms=1800` 是从试验网里调出来的。
真实目标的抖动分布完全不同——共享主机一次 GC、CDN 一次回源、前置代理一次排队，都能把
30ms 的接口量出 40ms 的离散度。拿默认值直接打，只会得到一串「采样抖动过大，需要重测」，
既浪费预算，也让人误以为"目标没有时间注入"。

所以这里只做一件事：**同一个请求发 N 次，把分布画出来，换算成判定阈值**。
不猜、不套模板、不改目标状态（方法默认 GET，载荷为空，L1）。

三个换算规则（都写在 `_suggest` 里，且只在注释里解释、不做黑箱）：
1. `cv_max = max(0.15, min(0.5, 2 * 实测CV))` —— 判定阈值至少留一倍余量，但不超过 0.5，
   否则等于放弃"抖动太大"这道闸；
2. `min_effect_ms` 取 `max(p90 + 4*MAD, 500)` 向上取整到 100ms 的三倍 —— 效应量要显著高于
   尾部噪声，同时给一个 500ms 的地板，避免把 20ms 抖动配成 60ms 阈值去误报；
3. 出现大量 0ms 采样时直接判 `clock`：那是本地时钟粒度问题（Windows `monotonic` 15.6ms），
   这时候谈阈值没有意义，先换 `perf_counter` 或换一台机器。
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .probe import ProbeRequest

# 建议值的地板与天花板，避免把阈值调到没有意义的位置
CV_FLOOR = 0.15
CV_CEIL = 0.50
EFFECT_FLOOR_MS = 500.0
EFFECT_CEIL_MS = 5000.0

# 绝对抖动地板：MAD 不到这个数，就不该因为"相对离散度"被判成 noisy。
# 30ms 的接口抖 7ms 是 0.23，听起来吓人，但对 500ms 级的判定阈值毫无影响；
# 反过来，把这种目标判成 noisy、再把 cv_max 放宽到 0.45，等于自觉放弃灵敏度。
# 取 8ms 的依据：Windows 定时器量化 15.6ms，一次 sleep(30ms) 的误差是两个刻度的
# 一半，MAD 上限约 7.8ms——这是操作系统给的下限，不是目标"不稳定"。
ABS_FLOOR_MS = 8.0


def _median(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _quantile(xs: Sequence[float], q: float) -> float:
    """线性插值分位数；样本少时比"取第 k 个"稳定。"""
    if not xs:
        return 0.0
    s = sorted(xs)
    if len(s) == 1:
        return s[0]
    pos = q * (len(s) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def _mad(xs: Sequence[float]) -> float:
    """绝对中位差。用 stddev 会被一次 GC 尖刺拉爆，中位数攻击也一样怕尖刺。"""
    if not xs:
        return 0.0
    m = _median(xs)
    return _median([abs(x - m) for x in xs])


@dataclass
class Calibration:
    url: str
    samples: List[float] = field(default_factory=list)
    zeros: int = 0
    warmup_dropped: int = 0
    verdict: str = "ok"            # ok | noisy | clock | slow | unreachable | truncated
    reason: str = ""
    notes: List[str] = field(default_factory=list)
    suggestion: Dict[str, Any] = field(default_factory=dict)

    # ---- 统计量（都在"丢冷启动、去过 0"之后的样本上算） ----
    @property
    def count(self) -> int:
        return len(self.samples)

    @property
    def p50(self) -> float:
        return _median(self.samples)

    @property
    def p90(self) -> float:
        return _quantile(self.samples, 0.90)

    @property
    def p99(self) -> float:
        return _quantile(self.samples, 0.99)

    @property
    def peak(self) -> float:
        return max(self.samples) if self.samples else 0.0

    @property
    def low(self) -> float:
        return min(self.samples) if self.samples else 0.0

    @property
    def mad(self) -> float:
        return _mad(self.samples)

    @property
    def cv(self) -> float:
        m = self.p50
        return (self.mad / m) if m > 0 else 0.0

    @property
    def spread(self) -> float:
        return (self.peak - self.low) if self.samples else 0.0

    def stats(self) -> Dict[str, float]:
        return {
            "count": float(self.count),
            "p50_ms": round(self.p50, 2),
            "p90_ms": round(self.p90, 2),
            "p99_ms": round(self.p99, 2),
            "min_ms": round(self.low, 2),
            "max_ms": round(self.peak, 2),
            "mad_ms": round(self.mad, 2),
            "cv": round(self.cv, 4),
            "spread_ms": round(self.spread, 2),
            "zeros": float(self.zeros),
            "warmup_dropped": float(self.warmup_dropped),
        }

    def to_json(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "verdict": self.verdict,
            "reason": self.reason,
            "notes": list(self.notes),
            "stats": self.stats(),
            "suggestion": dict(self.suggestion),
        }


class Calibrator:
    """在目标上量 N 次同一请求的耗时分布，给出时间类 oracle 的阈值建议。

    预算与证据语义完全复用现有链路：每次采样都走 `ProbeTool`（因此受范围、限速、
    预算、审计约束），耗时从 `timing_sample` 表读回来。校准本身不留 finding。
    """

    def __init__(self, ws, url: str, param_path: Optional[str] = None,
                 samples: int = 30, identity: str = "none", method: str = "GET",
                 level: str = "L1", timeout_s: float = 10.0):
        self.ws = ws
        self.url = url
        self.param_path = param_path
        self.samples = max(6, int(samples))
        self.identity = identity
        self.method = method
        self.level = level
        self.timeout_s = timeout_s

    def _suggest(self, cal: Calibration) -> None:
        cv = cal.cv
        noise = cal.p90 + 4.0 * cal.mad
        raw_effect = max(noise * 3.0, EFFECT_FLOOR_MS)
        effect = min(EFFECT_CEIL_MS, math.ceil(raw_effect / 100.0) * 100)
        cv_max = round(max(CV_FLOOR, min(CV_CEIL, 2.0 * cv)), 2)
        cal.suggestion = {
            # min_samples 是"过滤后至少要几个"；samples 是"要发几次"，
            # 因为执行器会先丢 1 个冷启动样本。
            "min_samples": 9 if cv > 0.10 else 5,
            "samples": (9 if cv > 0.10 else 5) + 1,
            "cv_max": cv_max,
            "abs_noise_ms": round(max(5.0, cal.mad * 2.0), 1),
            "min_effect_ms": int(effect),
            "alpha": 0.01,
        }
        if effect >= EFFECT_CEIL_MS:
            cal.notes.append("噪声太大：阈值已经顶到 %dms，建议换更稳定的时间窗或改用布尔盲注"
                             % int(EFFECT_CEIL_MS))
        if cal.p50 >= 1500.0:
            cal.notes.append("端点本身要 %.0fms：SLEEP 要明显大于它才分得开，"
                             "或者直接用布尔/报错型判定" % cal.p50)

    def run(self) -> Calibration:
        cal = Calibration(url=self.url)
        self._by_evidence: Dict[str, List[float]] = {}
        raw: List[float] = []
        truncated = False
        for i in range(self.samples):
            req = ProbeRequest(
                action_id="calib:%d" % i,
                url=self.url,
                method=self.method,
                identity=self.identity,
                label="calibrate",
                param_path=self.param_path,
                sample=1,
                timeout_s=self.timeout_s,
                level=self.level,
                headers_extra=(("Cache-Control", "no-store"),),
            )
            try:
                res = self.ws.probe.run(req)
            except Exception as exc:                    # 预算/范围/DNS 都是"停"，不是"崩"
                cal.verdict = "truncated"
                cal.reason = "%s: %s" % (type(exc).__name__, exc)
                truncated = True
                break
            if res.status != "ok":
                cal.verdict = "unreachable"
                cal.reason = "%s %s" % (res.status, res.reason) if res.reason else res.status
                break
            code = getattr(res.extract, "status", 200) if res.extract else 200
            if code >= 400:
                # 403/404 之类的"能连上但拿不到正常响应"没有分布可言：
                # 继续采样只会把预算耗在同一个错误上。
                cal.verdict = "unreachable"
                cal.reason = "HTTP %d" % code
                break
            if res.evidence_id:
                # 同一请求重复采样只产一条证据（内容寻址），样本挂在它下面。
                # 直接把 timings 读回来会越读越长，所以按 evidence 记最后一次读数。
                self._by_evidence[res.evidence_id] = self.ws.store.timings(res.evidence_id)
            if self.ws.budget.used >= self.ws.budget.max_requests:
                cal.notes.append("预算到顶，采样在 %d/%d 次处停止" % (len(raw), self.samples))
                break

        for got in self._by_evidence.values():
            raw.extend(got)
        cal.zeros = sum(1 for t in raw if t <= 0.0)
        live = [t for t in raw if t > 0.0]
        if len(live) > 5:
            cal.warmup_dropped = 1
            live = live[1:]
        cal.samples = live

        if cal.verdict in ("unreachable", "truncated"):
            return cal
        if len(live) < 5:
            cal.verdict = "clock" if cal.zeros else "truncated"
            cal.reason = ("采样里 %d 个 0ms：时钟粒度不足（Windows monotonic 15.6ms），"
                          "先确认传输层用的是 perf_counter" % cal.zeros) if cal.zeros else \
                         "有效样本只有 %d 个，不足以谈分布" % len(live)
            return cal

        self._suggest(cal)
        if cal.cv > CV_FLOOR and cal.mad <= ABS_FLOOR_MS:
            # 分母小导致的"假噪声"：绝对抖动在毫秒级，对判定阈值没有实际影响
            cal.verdict = "ok"
            cal.reason = ("绝对抖动只有 %.1fms（目标本身很快），相对离散度 %.2f 偏高是分母小的缘故，"
                          "对 %dms 级判定阈值没有影响" % (cal.mad, cal.cv, cal.suggestion["min_effect_ms"]))
        elif cal.cv > 0.25:
            cal.verdict = "noisy"
            cal.reason = "相对离散度 %.2f，同一请求的耗时会漂到两倍以上" % cal.cv
        elif cal.cv > CV_FLOOR:
            cal.verdict = "noisy"
            cal.reason = "相对离散度 %.2f，高于默认阈值 %.2f，已按实测放宽" % (cal.cv, CV_FLOOR)
        else:
            cal.verdict = "ok"
            cal.reason = "相对离散度 %.2f，默认 cv_max 够用" % cal.cv
        if cal.verdict == "ok":
            # 结论是"默认阈值够用"，建议值就必须是默认值——否则一边说够用、
            # 一边把 cv_max 放宽到 0.28，等于自己拆自己的闸。
            cal.suggestion["cv_max"] = CV_FLOOR
        return cal


def write_calibration(ws, cal: Calibration, name: str = "calibration.json") -> str:
    """落在工作区根目录（不是证据）：它是"配置建议"，不是"目标事实"。"""
    path = os.path.join(ws.root, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(cal.to_json(), fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
    return path
