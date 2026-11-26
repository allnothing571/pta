"""竞态演示：同一请求并发 N 发，看服务端把同一个操作接受了几次。

python demo_race.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import vhx  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import MockTransport, RawResponse  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
CODE = "SUMMER-2026"
WINDOW_MS = 8.0        # 判定与写入之间的窗口：真实竞态就住在这几毫秒里


class CouponServer(MockTransport):
    """优惠券核销接口。

    leaky：先查"用没用过"，睡 WINDOW_MS 再写 —— 这中间进来的请求看到的都是"没过"。
    guarded：查+写在同一把锁里，第二发起必然 409。
    deny：全部 403。
    """

    def __init__(self, mode="leaky"):
        super().__init__([])
        self.mode = mode
        self._lock = threading.Lock()
        self.redeemed = set()
        self.accepted = 0
        self.arrived = 0
        self.times = []

    def send(self, req, timeout_s=10.0):
        self.times.append(time.perf_counter())
        self.sent.append(req)
        t0 = time.perf_counter()
        try:
            data = json.loads((req.body or b"{}").decode("utf-8"))
        except ValueError:
            data = {}
        # 核销键是载荷写进去的标记；基线（不带标记）只是一次读，不消耗券
        code = data.get("name") or ""
        if not code:
            return RawResponse(status=200, reason="OK", http_version="HTTP/1.1",
                               headers=(("Content-Type", "application/json"),),
                               body=b'{"ok":true,"dry_run":true}',
                               t_send=t0, t_first_byte=t0, t_end=time.perf_counter())
        with self._lock:
            self.arrived += 1

        if self.mode == "deny":
            status, body = 403, b'{"error":"forbidden"}'
        elif self.mode == "guarded":
            # 正确实现：判定与扣减是原子的
            with self._lock:
                if code in self.redeemed:
                    status, body = 409, b'{"error":"already redeemed"}'
                else:
                    self.redeemed.add(code)
                    self.accepted += 1
                    status, body = 201, b'{"ok":true}'
        else:
            # 有缺陷的实现：查的时候还没写，窗口内全部放行
            with self._lock:
                seen = code in self.redeemed
            if seen:
                status, body = 409, b'{"error":"already redeemed"}'
            else:
                time.sleep(WINDOW_MS / 1000.0)
                with self._lock:
                    self.redeemed.add(code)
                    self.accepted += 1
                status, body = 201, b'{"ok":true}'

        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),),
                           body=body, t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


def template(burst: int = 5):
    raw = [t for t in vhx.TEMPLATES if t["id"] == "race-condition-idempotency"][0]
    if burst == raw["probe"]["burst"]:
        return vhx.load(raw)
    raw = json.loads(json.dumps(raw))
    raw["probe"]["burst"] = burst
    raw["oracle"]["args"]["burst"] = burst
    return vhx.load(raw)


def run_case(name, mode, expect, note, burst=5, approve=True):
    root = tempfile.mkdtemp(prefix="pta-race-demo-")
    try:
        init_workspace(root, Scope(engagement_id="DEMO-RACE", domains=("shop.test",),
                                   allow_private=True, rate_per_host=200, max_requests=200))
        srv = CouponServer(mode)
        ws = open_workspace(root, transport=srv, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/A/authorization", "Bearer A")
        if approve:
            ws.gate.decide("DEMO-RACE", "http_probe", "shop.test", "body:*", "write_marker",
                           "L2", "approve", scope="class")
        eng = Executor(ws.probe, ws.store, "DEMO-RACE")
        f = eng.run(template(burst), Target(url="http://shop.test/api/coupon/redeem",
                                            method="POST", param_path="body:*",
                                            identity_baseline="A", identity_probe="A",
                                            body_json={"code": CODE}))
        crit = Critic(ws).review_finding(f, apply=False)
        metrics = f.verdict.get("metrics") or {}
        ok = f.status == expect
        statuses = metrics.get("statuses") or []
        print("%-10s %-16s %-6.3f %-10s %-5s %s" % (
            name, f.status, f.confidence, crit.status, "OK" if ok else "FAIL", note))
        if statuses:
            spread = [round((t - srv.times[0]) * 1000.0, 1) for t in srv.times] if srv.times else []
            print("%-10s 并发 %d 发状态：%s  服务端实际接受 %d 次  请求预算 %d 发" % (
                "", len(statuses), " ".join(str(s) for s in statuses),
                srv.accepted, f.requests_used))
            print("%-10s 到达时刻(ms)：%s" % ("", spread))
        elif mode == "deny":
            print("%-10s 服务端实际接受 %d 次" % ("", srv.accepted))
        return ok
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    print("%-10s %-16s %-6s %-10s %-5s %s" % ("场景", "结论", "置信度", "Critic", "", "说明"))
    print("-" * 100)
    results = [
        run_case("leaky", "leaky", "confirmed", "判定与扣减之间有窗口：5 发全被接受"),
        run_case("guarded", "guarded", "refuted", "原子核销：只有 1 发 201，其余 409"),
        run_case("deny", "deny", "refuted", "接口要权限：全部 403，不构成竞态证据"),
        run_case("burst3", "leaky", "confirmed", "并发发数由模板 probe.burst 决定", burst=3),
        run_case("unapproved", "leaky", "pending_approval", "未审批：一发写请求都不发",
                 approve=False),
    ]
    ok = all(results)
    print("\n结果：%s" % ("OK（同一请求并发多发，多于一发被接受→确认；只有一发→判否；"
                        "被拒/未审批既不算有洞也不算没洞）" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
