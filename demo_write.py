"""写入型越权演示：A 改 B 的对象，B 回读能不能看到。

python demo_write.py
"""
from __future__ import annotations

import json
import os
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
from pta.transport import MockTransport, RawResponse  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"


class ObjectServer(MockTransport):
    """有状态的对象服务器：GET 读状态；PUT 看身份决定改不改。"""

    def __init__(self, mode="vuln"):
        super().__init__([])
        self.mode = mode
        self.state = {"id": 3, "name": "widget", "owner": "B"}
        self.writes = 0

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        identity = ""
        for k, v in req.headers:
            if k.lower() == "authorization":
                identity = v
        t0 = time.perf_counter()
        status, body = 200, json.dumps(self.state, sort_keys=True).encode("utf-8")
        if req.method.upper() in ("PUT", "PATCH", "POST"):
            self.writes += 1
            if self.mode == "deny" or (identity != "Bearer A" and self.mode != "allowall"):
                status, body = 403, b'{"error":"forbidden"}'
            elif self.mode == "reject":
                status, body = 422, b'{"error":"unknown field"}'
            else:
                try:
                    data = json.loads((req.body or b"{}").decode("utf-8"))
                except ValueError:
                    data = {}
                if self.mode != "ignore" and isinstance(data.get("name"), str):
                    self.state["name"] = data["name"]
                status, body = 204, b""
        headers = (("Content-Type", "application/json"),) if body else ()
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1", headers=headers, body=body,
                           t_send=t0, t_first_byte=t0, t_end=time.perf_counter())


def template():
    return vhx.load([t for t in vhx.TEMPLATES if t["id"] == "idor-write-object"][0])


def run_case(name, mode, expect, note, probe="A", approve=True):
    root = tempfile.mkdtemp(prefix="pta-write-demo-")
    try:
        init_workspace(root, Scope(engagement_id="DEMO-W", domains=("shop.test",),
                                   allow_private=True, rate_per_host=200, max_requests=200))
        ws = open_workspace(root, transport=ObjectServer(mode),
                            dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/A/authorization", "Bearer A")
        ws.vault.put("cred/B/authorization", "Bearer B")
        if approve:
            ws.gate.decide("DEMO-W", "http_probe", "shop.test", "body:*", "write_marker",
                           "L2", "approve", scope="class")
        eng = Executor(ws.probe, ws.store, "DEMO-W")
        f = eng.run(template(), Target(url="http://shop.test/api/items/3", method="PUT",
                                       param_path="body:*", identity_baseline="B",
                                       identity_probe=probe, body_json={"name": "widget"}))
        crit = Critic(ws).review_finding(f, apply=False)
        ok = f.status == expect
        metrics = f.verdict.get("metrics") or {}
        print("%-12s %-18s %-6.3f %-9s %-5s %s" % (
            name, f.status, f.confidence, crit.status, "OK" if ok else "FAIL", note))
        if metrics.get("marker_keys"):
            print("%-12s 回读标记：%s  变化字段：%d" % (
                "", ",".join(metrics["marker_keys"]), metrics.get("changed_count", 0)))
        return ok
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    print("%-12s %-18s %-6s %-9s %-5s %s" % ("场景", "结论", "置信度", "Critic", "", "说明"))
    print("-" * 96)
    results = [
        run_case("vuln", "vuln", "confirmed", "A 写入 → B 回读看到标记"),
        run_case("ignore", "ignore", "refuted", "200 但没写进对象"),
        run_case("reject", "reject", "refuted", "字段被校验拒绝（422）"),
        run_case("deny", "deny", "refuted", "写接口有对象级授权（403）"),
        run_case("same-id", "allowall", "refuted", "写入被接受但身份等于属主（自写自读）",
                 probe="B"),
        run_case("unapproved", "vuln", "pending_approval", "未审批：一次写请求都不发",
                 approve=False),
    ]
    ok = all(results)
    print("\n结果：%s" % ("OK（写后回读可见→确认；没写进/被拒/自写自读全部判否；未审批不出网）"
                        if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
