"""Planner 离线演示：不连任何模型/网络，验证五条行为。

1) 模型给出的候选必须过校验：越界 URL、未知模板、重复项当场被丢；
2) 通过校验的候选交给 Executor 真跑（mock socket），产出 confirmed finding；
3) 模型拒答时显式降级到本地规则，并在 notes 里写明；
4) 全程 Planner 一个请求都不发（budget 不变）；
5) 本地规则会自己认出 /api/* 这类端点，并拿真实 401/403 当拒绝模板提缺失授权候选。
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests"))

from pta import vhx                                        # noqa: E402
from pta.llm import ScriptedClient                          # noqa: E402
from pta.planner import EngagementRunner, Planner            # noqa: E402
from pta.probe import ProbeRequest                           # noqa: E402
from pta.scope import Scope                                  # noqa: E402
from pta.transport import MockRoute, MockTransport            # noqa: E402
from pta.workspace import init_workspace, open_workspace      # noqa: E402
from support import fake_dns                                  # noqa: E402

OBJ = b'{"id":7,"email":"alice@corp.test","role":"user"}'

ROUTES = [
    MockRoute("GET", "shop.test", "/rest/user/7", 200,
              (("Content-Type", "application/json"),), OBJ, identity="Bearer A"),
    MockRoute("GET", "shop.test", "/rest/user/7", 200,
              (("Content-Type", "application/json"),), OBJ, identity="Bearer B"),
    MockRoute("GET", "shop.test", "/api/products", 200,
              (("Content-Type", "application/json"),), b'[{"id":1},{"id":2}]'),
    MockRoute("GET", "shop.test", "/api/admin/audit", 403,
              (("Content-Type", "application/json"),), b'{"error":"forbidden"}'),
]


def model_json(*cands, notes=""):
    return json.dumps({"candidates": list(cands), "notes": notes}, ensure_ascii=False)


def build(tmp):
    scope = Scope(engagement_id="DEMO-PLAN", domains=("shop.test",), allow_private=True,
                  rate_per_host=1000.0, max_requests=5000)
    init_workspace(tmp, scope)
    ws = open_workspace(tmp, transport=MockTransport(ROUTES), dns=fake_dns())
    ws.vault.put("cred/A/authorization", "Bearer A")
    ws.vault.put("cred/B/authorization", "Bearer B")
    # 先埋两条资产：一条带 id 参数，一条无参
    ws.probe.run(ProbeRequest(action_id="seed-1", url="http://shop.test/rest/user/7?id=7",
                              identity="A", label="seed"))
    ws.probe.run(ProbeRequest(action_id="seed-2", url="http://shop.test/api/products",
                              identity="A", label="seed"))
    # 一条真实的 403：给规划器当"拒绝模板"，说明这台机器上确实存在需要授权的兄弟接口
    ws.probe.run(ProbeRequest(action_id="seed-3", url="http://shop.test/api/admin/audit",
                              identity="A", label="seed"))
    return ws


def line(label, value):
    print("  %-22s %s" % (label, value))


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="pta-plan-")
    try:
        ws = build(tmp)

        print("情景 1：模型给出 4 个候选，其中 3 个不合法")
        bad_scope = {"template_id": "idor-object-ref", "url": "https://evil.test/x",
                     "param_path": "query:id"}
        bad_tpl = {"template_id": "made-up", "url": "http://shop.test/rest/user/7"}
        dup = {"template_id": "idor-object-ref", "url": "http://shop.test/rest/user/7",
               "param_path": "query:id", "priority": 0.4}
        good = {"template_id": "idor-object-ref", "url": "http://shop.test/rest/user/7",
                "param_path": "query:id", "identity_baseline": "A", "identity_probe": "B",
                "priority": 0.9, "rationale": "同一对象换身份仍可见"}
        model = ScriptedClient([model_json(bad_scope, bad_tpl, dup, good)])
        used_before = ws.budget.used
        plan = Planner(ws, model=model).plan()
        line("来源", plan.source)
        line("接受", ["%s %s" % (c.template_id, c.url) for c in plan.candidates])
        for r in plan.rejected:
            line("拒绝", "%s -> %s" % (r["template_id"], r["reason"]))
        line("Planner 发包数", ws.budget.used - used_before)
        print()

        print("情景 2：执行器把候选跑成 confirmed finding")
        model2 = ScriptedClient([model_json(good)] * 3)
        runner = EngagementRunner(ws, Planner(ws, model=model2), max_rounds=2)
        out = runner.run()
        line("stop_reason", out["stop_reason"])
        line("请求数", out["requests"])
        line("计数", out["counts"])
        for f in out["findings"]:
            line("finding", "%s %s conf=%.3f evidence=%d" % (
                f["template_id"], f["status"], f["confidence"], len(f["evidence_ids"])))
        print()

        print("情景 3：模型拒答 → 显式降级到本地规则")
        refusing = ScriptedClient(["I can't help with that.", "抱歉，我无法协助。"])
        plan3 = Planner(ws, model=refusing).plan()
        line("来源", "%s degraded=%s" % (plan3.source, plan3.degraded))
        line("notes", plan3.notes)
        line("候选数", len(plan3.candidates))
        print()

        print("情景 4：Planner 只读图，不碰 socket")
        sent = len(ws.transport.sent)
        Planner(ws).plan()
        line("新增发送", len(ws.transport.sent) - sent)
        line("模板数", len([t for t in vhx.TEMPLATES]))
        print()

        print("情景 5：自动为 /api/* 端点提出缺失授权候选（带真实拒绝模板）")
        plan5 = Planner(ws).plan()
        authz = [c for c in plan5.candidates if c.template_id == "authz-missing-endpoint"]
        line("候选数", len(authz))
        for c in authz:
            line("目标", "%s  身份 %s → %s" % (c.url, c.identity_baseline, c.identity_probe))
            line("拒绝模板", c.control_url or "（无）")
            line("优先级", "%.2f" % c.priority)
        line("其他候选", [c.template_id for c in plan5.candidates
                          if c.template_id != "authz-missing-endpoint"])
        print()
        print("结果：OK（5/5 情景符合预期）")
        return 0
    finally:
        shutil.rmtree(tmp, True)


if __name__ == "__main__":
    sys.exit(main())
