"""P1.9 批量赋值演示：mass-assignment-privilege 判"多塞的权限字段有没有真的生效"。

场景与判读：
  vuln    → 响应里 role 从 user 变 admin、is_admin 变 true  → confirmed 0.90
  ignore  → 服务端 200 但把字段丢了，响应仍是 user          → refuted 0.20（字段被忽略）
  reject  → 未知字段被校验拒绝（422）                        → refuted 0.00
  deny    → 写接口另有授权校验（403）                        → refuted 0.00
  no-corpus → 没给合法请求体，baseline 都写不进去            → refuted 0.00
  unapproved → L2 没有审批，probe 根本没发出去               → pending_approval

python demo_mass_assign.py
"""
from __future__ import annotations

import copy
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
from pta.transport import RawResponse, Transport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
URL = "http://app.test/api/profile"
USER_BODY = b'{"id":7,"name":"alice","role":"user","is_admin":false}'
ADMIN_BODY = b'{"id":7,"name":"alice","role":"admin","is_admin":true}'
CORPUS = {"name": "alice"}

CASES = [
    ("vuln：权限字段被写库", "vuln", "confirmed", "role user→admin"),
    ("ignore：字段被静默丢弃", "ignore", "refuted", "响应仍是 user"),
    ("reject：字段被校验拒绝", "reject", "refuted", "422 未知字段"),
    ("deny：写接口另有授权", "deny", "refuted", "403 无权限"),
]


class ShopTransport(Transport):
    """一个"用户资料"接口：只有带 name 的合法写入才成功。"""

    name = "shop"

    def __init__(self, mode):
        self.mode = mode
        self.sent = []

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        try:
            data = json.loads((req.body or b"{}").decode("utf-8"))
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        if self.mode == "deny":
            status, body = 403, b'{"error":"forbidden"}'
        elif "name" not in data:
            status, body = 400, b'{"error":"name is required"}'
        else:
            escalated = (str(data.get("role", "")).lower() in ("admin", "administrator")
                         or data.get("is_admin") in (True, "true", 1))
            if not escalated:
                status, body = 200, USER_BODY
            elif self.mode == "vuln":
                status, body = 200, ADMIN_BODY
            elif self.mode == "reject":
                status, body = 422, b'{"error":"unknown field: role"}'
            else:
                status, body = 200, USER_BODY       # ignore
        t = time.monotonic()
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),),
                           body=body, t_send=t, t_first_byte=t, t_end=time.monotonic())


def template():
    return vhx.load(copy.deepcopy(
        [t for t in vhx.TEMPLATES if t["id"] == "mass-assignment-privilege"][0]))


def run_case(name, mode, expect, note, approve=True, body_json=None):
    tmp = tempfile.mkdtemp(prefix="pta-mass-")
    try:
        scope = Scope(engagement_id="ENG-MASS", domains=("app.test",), allow_private=True,
                      rate_per_host=1000.0, max_requests=200)
        init_workspace(tmp, scope)
        tx = ShopTransport(mode)
        ws = open_workspace(tmp, transport=tx, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
        if approve:
            ws.gate.decide("ENG-MASS", "http_probe", "app.test", "body:*", "extra_field",
                           "L2", "approve", scope="class")
        target = Target(url=URL, method="POST", param_path="body:*",
                        identity_baseline="A", identity_probe="A",
                        body_json=dict(CORPUS) if body_json is None else body_json)
        finding = Executor(ws.probe, ws.store, "ENG-MASS").run(template(), target)
        crit = Critic(ws).review_finding(finding)
        return {"name": name, "status": finding.status, "conf": finding.confidence,
                "requests": finding.requests_used, "evidence": len(finding.evidence_ids),
                "critic": crit.status, "note": note,
                "rationale": finding.verdict.get("rationale", ""),
                "stop": finding.stop_reason,
                "ok": finding.status == expect}
    finally:
        shutil.rmtree(tmp, True)


def main():
    print("模板：mass-assignment-privilege（L2，CWE-915）")
    print("判定：附加权限字段被写库且等级真的涨了 → confirmed；字段被忽略/拒绝/无权限 → refuted")
    print("")
    print("场景".ljust(26) + "结论".ljust(12) + "置信度".ljust(9) + "请求".ljust(6) +
          "证据".ljust(6) + "Critic".ljust(9) + "说明")
    print("-" * 100)
    all_ok = True
    for name, mode, expect, note in CASES:
        r = run_case(name, mode, expect, note)
        all_ok = all_ok and r["ok"] and r["critic"] == "kept"
        print(name.ljust(26) + r["status"].ljust(12) + ("%.3f" % r["conf"]).ljust(9) +
              str(r["requests"]).ljust(6) + str(r["evidence"]).ljust(6) +
              r["critic"].ljust(9) + r["note"])

    print("")
    r = run_case("no-corpus：没给合法字段", "vuln", "refuted", "baseline 都写不进去",
                 body_json={})
    all_ok = all_ok and r["ok"]
    print("no-corpus：body_json 为空 → %s %.3f（%s）"
          % (r["status"], r["conf"], r["rationale"]))

    r = run_case("unapproved：L2 未审批", "vuln", "pending_approval", "probe 没有发出去",
                 approve=False)
    all_ok = all_ok and r["status"] == "pending_approval" and r["stop"].startswith("pending_approval")
    print("unapproved：不批 L2 → %s，stop=%s，finding 证据 %d 条（baseline 已入库但不足以判定）"
          % (r["status"], r["stop"].split(":")[0], r["evidence"]))

    print("")
    print("理由示例（vuln）：%s" % run_case(*CASES[0])["rationale"])
    print("")
    print("结果：%s" % ("OK（写库→确认；忽略/拒绝/无权限/无样本全部判否；未审批不出网）"
                       if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
