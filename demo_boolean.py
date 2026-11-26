"""P1.11 布尔盲注演示：sqli-boolean-blind 判"差异是不是布尔条件造成的"。

场景与判读：
  vuln      → 1=1 走正常分支、1=2 被过滤掉                      → confirmed 0.88+
  empty     → 1=2 直接返回空结果集（差异更彻底）                  → confirmed 0.93
  ignore    → 服务端把参数当字符串，两份响应一模一样               → refuted（参数没进 SQL）
  broken    → 单引号让查询崩了，1=1 也变成错误页                   → refuted（差异来自崩溃）
  reversed  → 假条件才像基线、真条件少了几行（分流逻辑相反）        → refuted（方向相反）
  waf       → 带单引号一律 403                                     → refuted（被拦，0 分）
  no-base   → 没给基线身份                                         → refuted（缺 baseline）

python demo_boolean.py
"""
from __future__ import annotations

import copy
import os
import shutil
import sys
import tempfile
import time
from urllib.parse import unquote_plus

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from pta import vhx  # noqa: E402
from pta.critic import Critic  # noqa: E402
from pta.executor import Executor, Target  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.transport import RawResponse, Transport  # noqa: E402
from pta.workspace import init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
URL = "http://app.test/api/items?q=widget"

BIG = b'{"items":[' + b",".join(
    b'{"id":%d,"name":"item-%d","price":%d}' % (i, i, i * 7) for i in range(1, 13)) + b"]}"
SMALL = b'{"items":[]}'
MEDIUM = BIG[: len(BIG) * 3 // 4] + b"]}"
BROKEN = b'{"error":"internal","trace":"SQL syntax error near \'1\'"}'

CASES = [
    ("vuln：1=2 被过滤", "vuln", "confirmed"),
    ("empty：1=2 返回空集", "empty", "confirmed"),
    ("ignore：参数被当字符串", "ignore", "refuted"),
    ("broken：单引号打崩页面", "broken", "refuted"),
    ("reversed：方向相反", "reversed", "refuted"),
    ("waf：单引号一律 403", "waf", "refuted"),
]


class SearchTransport(Transport):
    """模拟搜索接口：只有真正进 SQL 的 1=2 才会让结果集变化。"""

    name = "search"

    def __init__(self, mode):
        self.mode = mode
        self.sent = []

    def send(self, req, timeout_s=10.0):
        self.sent.append(req)
        q = unquote_plus("&".join("%s=%s" % (k, v) for k, v in req.query))
        if self.mode == "waf" and "'" in q:
            return self._resp(403, b'{"error":"blocked by waf"}')
        if self.mode == "ignore":
            return self._resp(200, BIG)
        if "1'='2" in q:
            if self.mode == "empty":
                return self._resp(200, b"")
            return self._resp(200, SMALL if self.mode == "vuln" else BIG)
        if "1'='1" in q and self.mode == "broken":
            return self._resp(200, BROKEN)
        if "1'='1" in q and self.mode == "reversed":
            return self._resp(200, MEDIUM)
        return self._resp(200, BIG)

    @staticmethod
    def _resp(status, body):
        # 布尔盲注不看耗时，但 RawResponse 必须带时间戳（证据库里也会落一行 timing）
        t = time.perf_counter()
        return RawResponse(status=status, reason="OK" if status < 400 else "ERR",
                           http_version="HTTP/1.1",
                           headers=(("Content-Type", "application/json"),),
                           body=body, t_send=t, t_first_byte=t, t_end=t)


def template():
    return vhx.load(copy.deepcopy(
        [t for t in vhx.TEMPLATES if t["id"] == "sqli-boolean-blind"][0]))


def run_case(name, mode, expect, identity_baseline="A"):
    tmp = tempfile.mkdtemp(prefix="pta-bool-")
    try:
        scope = Scope(engagement_id="ENG-BOOL", domains=("app.test",), allow_private=True,
                      rate_per_host=1000.0, max_requests=100)
        init_workspace(tmp, scope)
        tx = SearchTransport(mode)
        ws = open_workspace(tmp, transport=tx, dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
        ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
        target = Target(url=URL, method="GET", param_path="query:q",
                        identity_baseline=identity_baseline, identity_probe="A")
        finding = Executor(ws.probe, ws.store, "ENG-BOOL").run(template(), target)
        crit = Critic(ws).review_finding(finding)
        return {"name": name, "status": finding.status, "conf": finding.confidence,
                "requests": finding.requests_used, "evidence": len(finding.evidence_ids),
                "critic": crit.status, "rationale": finding.verdict.get("rationale", ""),
                "metrics": finding.verdict.get("metrics", {}),
                "stop": finding.stop_reason, "ok": finding.status == expect,
                "votes": [i.code for i in crit.blocks]}
    finally:
        shutil.rmtree(tmp, True)


def main():
    print("模板：sqli-boolean-blind（L1，CWE-89）")
    print("判定：真条件≈基线 且 假条件偏离 且 两份注入彼此不同 → confirmed（三角关系，缺一不算）")
    print("")
    print("场景".ljust(24) + "结论".ljust(10) + "置信度".ljust(8) + "请求".ljust(5) +
          "证据".ljust(5) + "Critic".ljust(9) + "真/假相似度")
    print("-" * 96)
    all_ok = True
    for name, mode, expect in CASES:
        r = run_case(name, mode, expect)
        m = r["metrics"]
        sim = ("%.3f" % m["similarity_true_false"]) if "similarity_true_false" in m else "-"
        all_ok = all_ok and r["ok"] and r["critic"] == "kept"
        print(name.ljust(24) + r["status"].ljust(10) + ("%.3f" % r["conf"]).ljust(8) +
              str(r["requests"]).ljust(5) + str(r["evidence"]).ljust(5) +
              r["critic"].ljust(9) + sim)

    print("")
    r = run_case("no-base：没有基线身份", "vuln", "refuted", identity_baseline="none")
    all_ok = all_ok and r["ok"]
    print("no-base：不给 baseline 身份 → %s %.3f（%s）"
          % (r["status"], r["conf"], r["rationale"]))

    vuln = run_case("vuln", "vuln", "confirmed")
    m = vuln["metrics"]
    print("")
    print("三角关系（vuln）：真/基 %.3f，假/基 %.3f，真/假 %.3f；长度 %d / %d / %d"
          % (m["similarity_true_base"], m["similarity_false_base"],
             m["similarity_true_false"], m["len_base"], m["len_true"], m["len_false"]))
    print("理由：%s" % vuln["rationale"])
    print("")
    print("结果：%s" % ("OK（真条件≈基线且假条件偏离→确认；参数被忽略/页面崩/方向相反/WAF/无基线全部判否）"
                       if all_ok else "FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
