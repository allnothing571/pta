"""P1.10 时间盲注演示：sqli-time-blind 判"延时是不是注入造成的"。

场景与判读：
  vuln      → 带 SLEEP 的请求稳定慢 2s                        → confirmed 0.90+
  fast      → 内网接口 2ms，抖动亚毫秒，注入抬到 200ms         → confirmed（不判成抖动）
  slow      → 接口本来就慢，注入与否没差别                     → refuted（低于阈值）
  jitter    → 基线自身抖动大（相对离散度超阈值）                → refuted（不可信，需重测）
  spike     → 只有一次卡住，其它样本回落到基线                  → refuted（中位数没动，尖刺不算）
  waf       → 载荷被 WAF 拦成 403                              → refuted（没有可比较的响应）
  no-base   → 模板没要求基线，且没给身份，比无可比                  → refuted（缺 baseline）
  unapproved → L2 没审批，注入请求没发出去                      → pending_approval

为了让演示跑得动，这里把 min_effect_ms 压到 150ms（判定逻辑与阈值取值无关），
真实模板默认 1800ms（SLEEP(2) 的保守下限）。

python demo_timing.py
"""
from __future__ import annotations

import copy
import os
import random
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import vhx  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import RawResponse, Transport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
URL = "http://app.test/api/item?id=7"
SLOW_URL = "http://app.test/api/item?id=7"
BODY = b'{"id":7,"name":"widget"}'

CASES = [
    ("vuln：SLEEP 真的生效", "vuln", "confirmed", "注入组稳定 +2s"),
    ("fast：内网 2ms 接口", "fast", "confirmed", "绝对抖动小，相对值大不算噪声"),
    ("slow：接口本来就慢", "slow", "refuted", "两组耗时没差别"),
    ("jitter：基线抖得厉害", "jitter", "refuted", "相对离散度超阈值"),
    ("spike：只有一次卡住", "spike", "refuted", "单次尖刺不改中位数"),
    ("waf：载荷被拦", "waf", "refuted", "403，无可比响应"),
]


class DelayTransport(Transport):
    """模拟一个条目接口：payload 里出现 SLEEP 才变慢，其余按 mode 造假象。"""

    name = "delay"

    def __init__(self, mode):
        self.mode = mode
        self.sent = []
        self.n = 0

    def _delay_ms(self, has_sleep):
        base, probe = 40.0, 400.0
        if self.mode == "slow":
            base = probe = 380.0
        elif self.mode == "jitter":
            return random.uniform(5.0, 320.0)
        elif self.mode == "fast":
            # 本地/内网接口：基线 2ms，抖动不到 1ms。相对离散度会被放大，
            # 但绝对抖动远低于噪声下限，不该判成"抖动过大"。
            jitter = random.uniform(-0.4, 0.4)
            return (200.0 if has_sleep else base / 20.0) + jitter
        elif self.mode == "spike":
            # 只有注入组的第一次采样卡 300ms，其余正常
            if has_sleep and self.n <= 1:
                return 420.0
            return base
        return probe if has_sleep else base

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        self.n += 1
        q = "&".join("%s=%s" % (k, v) for k, v in req.query)
        has_sleep = "SLEEP" in q
        if self.mode == "waf" and has_sleep:
            status, body = 403, b'{"error":"blocked by waf"}'
        else:
            status, body = 200, BODY
        t0 = time.perf_counter()
        time.sleep(self._delay_ms(has_sleep) / 1000.0)
        t1 = time.perf_counter()
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),),
                           body=body, t_send=t0, t_first_byte=t1, t_end=t1)


def template(min_effect_ms=150, require_baseline=True):
    raw = copy.deepcopy([t for t in vhx.TEMPLATES if t["id"] == "sqli-time-blind"][0])
    raw["oracle"]["args"]["min_effect_ms"] = min_effect_ms
    if not require_baseline:
        raw["probe"].pop("baseline", None)
    return vhx.load(raw)


def run_case(name, mode, expect, note, approve=True, identity_baseline="A",
             require_baseline=True):
    tmp = tempfile.mkdtemp(prefix="pta-time-")
    try:
        scope = Scope(engagement_id="ENG-TIME", domains=("app.test",), allow_private=True,
                      rate_per_host=1000.0, max_requests=200)
        init_workspace(tmp, scope)
        tx = DelayTransport(mode)
        ws = open_workspace(tmp, transport=tx, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
        if approve:
            ws.gate.decide("ENG-TIME", "http_probe", "app.test", "query:id", "delay_short",
                           "L2", "approve", scope="class")
        target = Target(url=URL if mode != "slow" else SLOW_URL, method="GET",
                        param_path="query:id",
                        identity_baseline=identity_baseline, identity_probe="A")
        finding = Executor(ws.probe, ws.store, "ENG-TIME").run(
            template(require_baseline=require_baseline), target)
        crit = Critic(ws).review_finding(finding)
        m = finding.verdict.get("metrics", {})
        return {"name": name, "status": finding.status, "conf": finding.confidence,
                "requests": finding.requests_used, "evidence": len(finding.evidence_ids),
                "critic": crit.status, "note": note,
                "rationale": finding.verdict.get("rationale", ""),
                "stop": finding.stop_reason, "metrics": m,
                "ok": finding.status == expect}
    finally:
        shutil.rmtree(tmp, True)


def main():
    print("模板：sqli-time-blind（L2，CWE-89）")
    print("判定：注入组中位耗时显著高于基线 + 两组都够稳 + bootstrap p < 0.01 → confirmed")
    print("")
    print("场景".ljust(24) + "结论".ljust(12) + "置信度".ljust(9) + "请求".ljust(6) +
          "证据".ljust(6) + "Critic".ljust(9) + "说明")
    print("-" * 100)
    all_ok = True
    for name, mode, expect, note in CASES:
        r = run_case(name, mode, expect, note)
        all_ok = all_ok and r["ok"] and r["critic"] == "kept"
        print(name.ljust(24) + r["status"].ljust(12) + ("%.3f" % r["conf"]).ljust(9) +
              str(r["requests"]).ljust(6) + str(r["evidence"]).ljust(6) +
              r["critic"].ljust(9) + r["note"])

    print("")
    r = run_case("no-base：没有基线身份", "vuln", "refuted", "只能比无可比",
                 identity_baseline="none", require_baseline=False)
    all_ok = all_ok and r["ok"]
    print("no-base：不给 baseline 身份 → %s %.3f（%s）"
          % (r["status"], r["conf"], r["rationale"]))

    # 等审批不是"判否"：状态自己说话，面板才不会把它显示成一条 0 分 refuted
    r = run_case("unapproved：L2 未审批", "vuln", "pending_approval",
                 "注入请求没发出去", approve=False)
    all_ok = all_ok and r["status"] == "pending_approval" and r["stop"].startswith("pending_approval")
    print("unapproved：不批 L2 → %s，stop=%s，证据 %d 条"
          % (r["status"], r["stop"].split(":")[0], r["evidence"]))

    vuln = run_case(*CASES[0])
    m = vuln["metrics"]
    print("")
    print("采样细节（vuln）：基线中位 %.0fms / 注入中位 %.0fms，差值 %.0fms，"
          "相对离散度 %.3f/%.3f，p=%.4f，丢弃冷启动 %d 个"
          % (m["baseline_median_ms"], m["probe_median_ms"], m["effect_ms"],
             m["cv_baseline"], m["cv_probe"], m["p_value"], m["warmup_dropped"]))
    print("理由：%s" % vuln["rationale"])
    print("")
    print("结果：%s" % ("OK（真延时/内网快接口→确认；无差别/抖动/尖刺/WAF/无基线全部判否；未审批不出网）"
                       if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
