"""Critic 离线演示：六种复核结论，全程不发一个请求。"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))
sys.path.insert(0, os.path.join(HERE, "tests"))

from pta import vhx                                            # noqa: E402
from pta.critic import Critic                                   # noqa: E402
from pta.executor import Executor, Target                       # noqa: E402
from pta.llm import ScriptedClient                              # noqa: E402
from pta.probe import ProbeRequest                              # noqa: E402
from pta.scope import Scope                                     # noqa: E402
from pta.transport import MockRoute, MockTransport               # noqa: E402
from pta.workspace import init_workspace, open_workspace          # noqa: E402
from support import fake_dns, idor_routes                         # noqa: E402

TPL = "idor-object-ref"


def build(tmp):
    scope = Scope(engagement_id="DEMO-CRITIC", domains=("app.test",), allow_private=True,
                  rate_per_host=1000.0, max_requests=5000)
    init_workspace(tmp, scope)
    routes = idor_routes() + [MockRoute("GET", "app.test", "/api/other", 200, (), b'{"ok":1}')]
    ws = open_workspace(tmp, transport=MockTransport(routes), dns=fake_dns())
    ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
    ws.vault.put("cred/B/authorization", "Bearer TOKEN-B")
    return ws


def run_idor(ws, probe="B"):
    tpl = vhx.load([t for t in vhx.TEMPLATES if t["id"] == TPL][0])
    return Executor(ws.probe, ws.store, ws.scope.engagement_id).run(
        tpl, Target(url="http://app.test/api/users/1",
                    identity_baseline="A", identity_probe=probe))


def put(ws, fid, evidence_ids, confidence=0.9, verdict=None):
    ws.store.put_finding({"id": fid, "engagement_id": ws.scope.engagement_id,
                          "template_id": TPL, "title": "手工 finding",
                          "status": "confirmed", "confidence": confidence,
                          "evidence_ids": list(evidence_ids),
                          "verdict": verdict or {"metrics": {}, "rationale": "demo"},
                          "created_at": "2026-11-09T00:00:00Z"})


def row_of(ws, fid):
    for r in ws.store.list_findings(ws.scope.engagement_id):
        if r["id"] == fid:
            return r
    raise KeyError(fid)


def show(tag, crit):
    print("  %-26s %-8s blocks=%s warns=%s" % (
        tag, crit.status, [b.code for b in crit.blocks], [w.code for w in crit.warnings]))


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="pta-critic-")
    try:
        ws = build(tmp)

        print("① 干净 confirmed：应当保留")
        f = run_idor(ws)
        show("clean", Critic(ws).review_finding(f))

        print("② 证据被改过一个字节：应当否决")
        row = ws.store.get_evidence_row(f.evidence_ids[0])
        path = ws.cas.path_for(row["body_sha256"])
        blob = ws.cas.get(row["body_sha256"])
        with open(path, "wb") as fh:
            fh.write(ws.cas.cipher.encrypt(b"tampered"))
        try:
            show("tampered", Critic(ws).review_finding(f))
        finally:
            with open(path, "wb") as fh:
                fh.write(ws.cas.cipher.encrypt(blob))

        print("③ 同身份配对（越权证明不成立）：应当否决")
        same = run_idor(ws, probe="A")
        put(ws, "same-id", same.evidence_ids)
        show("same_identity", Critic(ws).review_row(row_of(ws, "same-id")))

        print("④ 只有一条证据却要配对判定：应当否决")
        put(ws, "one-ev", [f.evidence_ids[0]])
        show("one_evidence", Critic(ws).review_row(row_of(ws, "one-ev")))

        print("⑤ 同模板已有另一条 confirmed：只提醒")
        other = ws.probe.run(ProbeRequest(action_id="o", url="http://app.test/api/other",
                                          identity="A", label="other"))
        put(ws, "dup1", [other.evidence_id])
        show("duplicate", Critic(ws).review_finding(f))

        print("⑥ 模型复核否决：只否决、不提升")
        model = ScriptedClient([json.dumps(
            {"decision": "reject", "reasons": ["响应像登录跳转，不能证明越权"]},
            ensure_ascii=False)])
        show("model_veto", Critic(ws, model=model).review_finding(f))

        print()
        sent, used = len(ws.transport.sent), ws.budget.used
        Critic(ws).review_all(apply=False)
        print("  复核期间新增发包 %d，新增预算消耗 %d" % (
            len(ws.transport.sent) - sent, ws.budget.used - used))
        statuses = {}
        for r in ws.store.list_findings(ws.scope.engagement_id):
            statuses[r["status"]] = statuses.get(r["status"], 0) + 1
        print("  库内 finding 状态分布：%s" % statuses)
        print()
        print("结果：OK（6 种结论 + 零发包）")
        return 0
    finally:
        shutil.rmtree(tmp, True)


if __name__ == "__main__":
    sys.exit(main())
