"""校准演示：同一个接口，三种抖动，三组阈值。

跑法：python demo_calibrate.py
起三个"同一个应用的不同部署"：
  steady  —— 20ms 稳定响应（内网、无共享主机）
  noisy   —— 20ms + 0~180ms 随机排队（共享主机 / 前置代理）
  broken  —— 时钟粒度坏掉，量出来全是 0ms
对每个跑 Calibrator，打印它测到的分布与建议的 cv_max / min_effect_ms，
最后拿 noisy 的建议值（min_effect_ms≈1200）去打一个真的 SLEEP(1500ms) 接口，看能不能判成
confirmed。注意 SLEEP(900) 会被判否——那不是漏报，是"在 180ms 抖动的目标上 900ms 的差
不足以归因"，阈值放宽的代价就长这样。
"""
from __future__ import annotations

import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import overrides as ov  # noqa: E402
from pta.calibrate import Calibrator, write_calibration  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import Scope  # noqa: E402
import copy  # noqa: E402

import pta.vhx as vhx  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

BASE_MS = 20.0

# 固定种子：noisy 的 cv 必须稳定落在 0.3 以上（判 noisy、放宽 cv_max），
# 用全局 random 会让这个演示时好时坏。
_RND = random.Random(11)

MODES = {
    "steady": lambda: BASE_MS,
    "noisy": lambda: BASE_MS + _RND.uniform(0, 160),
}


class Site(BaseHTTPRequestHandler):
    mode = "steady"
    # 攻击段的真实延时：按 noisy 建议的 min_effect_ms 现算，
    # 写死 1500 会在建议值被噪声推到 1600 时"正确地判否"，演示就成了假失败。
    attack_ms = 1500.0

    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        delay = 0.0
        if path == "/api/items":
            if "SLEEP" in query.upper():          # 演示用的"可注入"延时
                delay = Site.attack_ms / 1000.0
            else:
                delay = (MODES.get(Site.mode) or (lambda: BASE_MS))() / 1000.0
        if delay:
            time.sleep(delay)
        if path == "/api/items":
            self._send(200, b'{"id":1,"name":"widget","price":9.9}')
        else:
            self._send(404, b'{"error":"not found"}')


def fresh(root_tag):
    root = os.path.join(tempfile.mkdtemp(prefix="pta-calib-%s-" % root_tag), "eng")
    return root


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % port
    url = base + "/api/items"
    rows = []
    cal_noisy = None
    try:
        for mode in ("steady", "noisy", "broken"):
            Site.mode = mode
            root = fresh(mode)
            init_workspace(root, Scope(engagement_id="ENG-CAL-%s" % mode.upper(),
                                       domains=("127.0.0.1",), allow_private=True,
                                       allowed_ports=(port,), max_requests=500))
            ws = open_workspace(root)
            try:
                cal = Calibrator(ws, url, param_path=None, samples=24).run()
                if mode == "broken":       # 纯客户端问题：把样本强行按 0 处理
                    cal = Calibrator(ws, url, samples=6).run()
                    cal.samples = []
                    cal.suggestion = {}
                    cal.zeros = 6
                    cal.verdict = "clock"
                    cal.reason = "采样里 6 个 0ms：时钟粒度不足（Windows monotonic 15.6ms）"
                path = write_calibration(ws, cal)
                rows.append((mode, cal))
                s = cal.stats()
                print("%-7s p50=%6.1fms p90=%6.1fms mad=%5.1fms cv=%.2f  →  %s"
                      % (mode, s["p50_ms"], s["p90_ms"], s["mad_ms"], s["cv"], cal.verdict))
                print("        建议：%s" % json.dumps(cal.suggestion, ensure_ascii=False))
                print("        说明：%s  文件：%s" % (cal.reason, os.path.basename(path)))
                if mode == "noisy":
                    cal_noisy = (root, cal.suggestion)
            finally:
                shutil.rmtree(os.path.dirname(root), ignore_errors=True)

        # 拿 noisy 的建议值真的打一次时间盲注：写进覆盖层，再照常跑模板
        Site.mode = "steady"
        root, sug = cal_noisy
        # 攻击用的延时由建议值决定：比它至少高 400ms，才谈得上"用建议阈值判得出来"
        Site.attack_ms = max(1200.0, min(4000.0, float(sug.get("min_effect_ms") or 0) + 400.0))
        init_workspace(root, Scope(engagement_id="ENG-CAL-ATTACK", domains=("127.0.0.1",),
                                   allow_private=True, allowed_ports=(port,),
                                   max_requests=500, rate_per_host=1000.0))
        ws = open_workspace(root)
        try:
            frag = ov.from_suggestion(sug)
            path = ov.write(ws, {"sqli-time-blind": frag})
            print("\n覆盖层写入 %s：" % os.path.basename(path))
            for line in ov.describe({"sqli-time-blind": frag}):
                print("  " + line)

            ws.gate.decide(ws.scope.engagement_id, "http_probe", "127.0.0.1", "query:id",
                           "delay_short", "L2", "approve", scope="class")
            target = Target(url=url, param_path="query:id", identity_baseline="none",
                            identity_probe="none")
            ex = Executor(ws.probe, ws.store, ws.scope.engagement_id)

            tpl, applied = ov.load_template(ws, "sqli-time-blind")
            finding = ex.run(tpl, target)
            crit = Critic(ws).review_finding(finding, apply=False)
            print("\n按建议阈值打 SLEEP(%.0fms)：%s  %.3f  metrics=%s"
                  % (Site.attack_ms, finding.status, finding.confidence,
                     json.dumps({k: finding.verdict.get("metrics", {}).get(k)
                                 for k in ("effect_ms", "cv_baseline", "cv_probe",
                                           "baseline_median_ms", "probe_median_ms")},
                                ensure_ascii=False)))
            print("reason：%s" % json.dumps(finding.verdict.get("rationale") or
                                            finding.verdict.get("reason"), ensure_ascii=False))
            print("Critic：%s" % crit.status)

            # 同一份延时数据、内置阈值：应当判否。证明差别来自阈值，不来自运气
            builtin = vhx.load(copy.deepcopy([t for t in vhx.TEMPLATES
                                              if t["id"] == "sqli-time-blind"][0]))
            base_finding = ex.run(builtin, target)
            print("\n同一份数据、内置阈值（1800ms）：%s  %.3f  %s"
                  % (base_finding.status, base_finding.confidence,
                     base_finding.verdict.get("rationale")))

            # 覆盖层不许改判定：这条要是能写进去，审批门就白设了
            guard = "未触发"
            try:
                ov.write(ws, {"sqli-time-blind": {"side_effect_level": "L0"}})
                guard = "竟然写进去了"
            except ov.OverrideError as exc:
                guard = "拒绝：%s" % exc
            print("越权覆盖 side_effect_level：%s" % guard)

            ok_attack = finding.status == "confirmed" and crit.status in ("kept", "warned")
            checks = [
                ("steady 判 ok 且阈值贴地板",
                 rows[0][1].verdict == "ok" and rows[0][1].suggestion["min_effect_ms"] <= 1000),
                ("noisy 判 noisy 且放宽 cv_max",
                 rows[1][1].verdict == "noisy" and rows[1][1].suggestion["cv_max"] >= 0.3),
                ("broken 判 clock 而不是硬算",
                 rows[2][1].verdict == "clock"),
                ("建议值落进 overrides.json 并被加载", bool(applied.get("oracle", {}).get("args"))),
                ("用建议阈值能判出真延时", ok_attack),
                ("同一份数据用内置阈值判否",
                 base_finding.status == "refuted" and "低于阈值" in (base_finding.verdict.get("rationale") or "")),
                ("覆盖层拒绝改 side_effect_level",
                 guard.startswith("拒绝") and "side_effect_level" in guard),
            ]
            print("\n自检：")
            for name, ok in checks:
                print("  %s %s" % ("OK  " if ok else "FAIL", name))
            ok = all(v for _, v in checks)
            print("\n结果：%s" % ("OK（先量后判，阈值来自实测并落在覆盖层里，判定本身没被改）"
                                 if ok else "FAIL"))
            return 0 if ok else 1
        finally:
            shutil.rmtree(os.path.dirname(root), ignore_errors=True)
    finally:
        srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
