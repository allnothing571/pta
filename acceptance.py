"""P0 六条验收，一次跑完。

用法：
  python acceptance.py            # 离线 mock 目标（默认可复现）
  python acceptance.py --root W   # 复用已有工作区

每条都打印 OK/FAIL 与关键证据，退出码非 0 表示未通过。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pta.api import make_server  # noqa: E402
from pta.errors import EvidenceCorrupted  # noqa: E402
from pta.models import verdict_status  # noqa: E402
from pta.oracles import DifferentialObjectAccess, load_observations  # noqa: E402
from pta.probe import ProbeRequest  # noqa: E402
from pta.scope import DnsPin, Scope  # noqa: E402
from pta.store import Store  # noqa: E402
from pta.transport import MockRoute, MockTransport  # noqa: E402
from pta.workspace import build_transport, init_workspace, open_workspace  # noqa: E402

PUBLIC_IP = "93.184.216.34"
OBJ = b'{"id":7,"email":"alice@corp.test","phone":"13800000000","role":"user"}'
RESULTS = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print("[%s] %s%s" % ("OK  " if ok else "FAIL", name, ("  -- " + detail) if detail else ""))


def routes():
    return [
        MockRoute("GET", "shop.test", "/rest/user/7", 200, (("Content-Type", "application/json"),),
                  OBJ, identity="Bearer TOKEN-A"),
        MockRoute("GET", "shop.test", "/rest/user/7", 200, (("Content-Type", "application/json"),),
                  OBJ, identity="Bearer TOKEN-B"),
        MockRoute("GET", "shop.test", "/api/ok", 200, (("Content-Type", "text/html"),), b"<html>ok</html>"),
        MockRoute("GET", "shop.test", "/api/fetch", 200, (("Content-Type", "text/plain"),), b"ok"),
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    args = ap.parse_args()

    root = args.root or tempfile.mkdtemp(prefix="pta-acc-")
    own = args.root is None
    scope = Scope(engagement_id="ACC-1", domains=("shop.test",), allow_private=True,
                  rate_per_host=500.0, max_requests=500)
    init_workspace(root, scope)
    ws = open_workspace(root, transport=MockTransport(routes()),
                        dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
    ws.vault.put("cred/A/authorization", "Bearer TOKEN-A")
    ws.vault.put("cred/B/authorization", "Bearer TOKEN-B")
    ws.probe.oob_host = "oob.test"
    print("工作区：%s\n" % root)

    # ① 范围拦截
    r = ws.probe.run(ProbeRequest(action_id="acc1", url="http://evil.example.com/x", label="acc1"))
    denied = ws.store.logs("ACC-1", "denied")
    check("① Scope 拦截 + action_log", r.status == "denied" and bool(denied),
          "%s / denied=%d" % (r.status, len(denied)))

    # ③ 采样合并（先做，后面复用证据）
    r3 = ws.probe.run(ProbeRequest(action_id="acc3", url="http://shop.test/rest/user/7",
                                   identity="A", label="sample", sample=5))
    rows = ws.store.list_evidence("ACC-1", "sample")
    check("③ 采样 5 次 = 1 条证据", len(rows) == 1 and rows[0]["sample_count"] == 5
          and len(ws.store.timings(r3.evidence_id)) == 5,
          "rows=%d samples=%d timings=%d" % (len(rows), rows[0]["sample_count"] if rows else -1,
                                             len(ws.store.timings(r3.evidence_id))))

    # ② replay + tamper
    out = ws.replayer.replay(r3.evidence_id)
    row = ws.store.get_evidence_row(r3.evidence_id)
    path = ws.cas.path_for(row["body_sha256"])
    with open(path, "rb") as fh:
        original = fh.read()
    with open(path, "wb") as fh:
        fh.write(original[:-1] + bytes([original[-1] ^ 0xFF]))
    tampered = False
    try:
        ws.replayer.replay(r3.evidence_id)
    except EvidenceCorrupted:
        tampered = True
    with open(path, "wb") as fh:  # 还原，后续步骤继续用同一份证据
        fh.write(original)
    check("② 证据可 replay 且篡改被检出", out["match"] and tampered,
          "match=%s tamper=%s" % (out["match"], tampered))

    # ④ L2 审批：pending → SSE → approve → 放行
    httpd, bus = make_server(ws, bus=ws.bus, port=0)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    import queue
    q = bus.subscribe()
    r4 = ws.probe.run(ProbeRequest(action_id="acc4", url="http://shop.test/api/fetch?url=x",
                                   identity="A", label="ssrf", param_path="query:url",
                                   payload_class="oob_url"))
    sse_ok = False
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            ev = q.get(timeout=0.3)
        except queue.Empty:
            continue
        if ev.get("type") == "approval_required":
            sse_ok = True
            break
    fp = r4.approval_fp
    req = urllib.request.Request(
        "http://127.0.0.1:%d/api/approvals/%s/decide" % (port, fp),
        data=json.dumps({"decision": "approve", "scope": "class"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        decided = json.loads(resp.read().decode())
    r4b = ws.probe.run(ProbeRequest(action_id="acc4b", url="http://shop.test/api/fetch?url=x",
                                    identity="A", label="ssrf", param_path="query:url",
                                    payload_class="oob_url"))
    check("④ L2 无审批→pending + SSE + 批准后放行",
          r4.status == "pending_approval" and sse_ok and decided.get("ok") and r4b.status == "ok",
          "first=%s sse=%s approve=%s second=%s" % (r4.status, sse_ok, decided.get("ok"), r4b.status))

    # ⑤ 无旁路：配置了代理就必须走代理
    proxied_scope = Scope(engagement_id="ACC-2", domains=("shop.test",), allow_private=True,
                          egress_proxy="127.0.0.1:1")
    tx = build_transport(proxied_scope)
    no_bypass = tx.name == "proxy-connect"
    from pta.budget import Budget
    from pta.approvals import ApprovalGate
    from pta.probe import ProbeTool
    from pta.vault import Vault
    from pta.cas import Cas
    store2 = Store(os.path.join(root, "acc2.sqlite"))
    ws2 = ProbeTool(scope=proxied_scope, store=store2,
                    cas=Cas(os.path.join(root, "cas2")), transport=tx,
                    gate=ApprovalGate(store2), budget=Budget(max_requests=100, rate_per_host=100),
                    vault=Vault(os.path.join(root, "vault2.json")),
                    dns=DnsPin(resolver=lambda h: [PUBLIC_IP]))
    r5 = ws2.run(ProbeRequest(action_id="acc5", url="http://shop.test/api/ok", label="bypass"))
    check("⑤ 关闭出口代理则全部失败（无旁路）", no_bypass and r5.status == "error",
          "transport=%s status=%s" % (tx.name, r5.status))

    httpd.shutdown()

    # ⑥ IDOR 全链路 → confirmed
    base = ws.probe.run(ProbeRequest(action_id="acc6a", url="http://shop.test/rest/user/7",
                                     identity="A", label="idor"))
    probe = ws.probe.run(ProbeRequest(action_id="acc6b", url="http://shop.test/rest/user/7",
                                      identity="B", label="idor"))
    obs = load_observations(ws.store, ws.cas, "ACC-1", "idor",
                            {base.evidence_id: "baseline", probe.evidence_id: "probe"})
    v = DifferentialObjectAccess().run(obs, DifferentialObjectAccess.Args())
    status = verdict_status(v.confidence)
    ws.store.put_finding({
        "id": "F-1", "engagement_id": "ACC-1", "template_id": "idor-object-ref",
        "title": "对象引用越权 /rest/user/7", "status": status, "confidence": v.confidence,
        "evidence_ids": [base.evidence_id, probe.evidence_id], "verdict": v.metrics,
        "created_at": "2026-11-09T00:00:00Z",
    })
    check("⑥ IDOR 一条 confirmed 且可溯源",
          status == "confirmed" and all(ws.store.get_evidence_row(e) for e in
                                        (base.evidence_id, probe.evidence_id)),
          "status=%s conf=%.3f sim=%.3f" % (status, v.confidence, v.metrics.get("similarity", 0)))

    print("\n预算快照：%s" % json.dumps(ws.budget.snapshot(), ensure_ascii=False))
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print("\n结果：%d/%d 通过" % (passed, len(RESULTS)))
    if own:
        keep = os.environ.get("PTA_KEEP") == "1"
        if keep:
            print("工作区保留：%s" % root)
        else:
            shutil.rmtree(root, ignore_errors=True)
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
